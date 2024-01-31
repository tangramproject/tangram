using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using Dawn;
using MessagePack;
using Microsoft.IO;
using Microsoft.Extensions.DependencyInjection;
using nng;
using nng.Native;
using Serilog;
using TangramXtgm.Extensions;
using TangramXtgm.Helper;
using TangramXtgm.Models;
using TangramXtgm.Network.Mesh;

namespace TangramXtgm.Network;

/// <summary>
/// Represents a gossip member store.
/// </summary>
public interface IGossipMemberStore
{
    Peer AddOrUpdateNode(MemberEvent memberEvent);
    Peer[] GetPeers();
    T GetServiceClient<T>(IPEndPoint serviceEndPoint) where T : IServiceClient;
    Task<T> SendAsync<T>(IPEndPoint serviceEndPoint, ReadOnlyMemory<byte> publicKey, ReadOnlyMemory<byte> value, int timeMs = 0, bool deserialize = true);
    Task SendAllAsync(ReadOnlyMemory<byte> msg);
    Task SendSelectedAsync(ReadOnlyMemory<byte> msg, Peer[] peers);
}

/// <summary>
/// Represents an empty message.
/// </summary>
public class EmptyMessage
{
}

/// <summary>
/// Represents a class for sending Internet Control Message Protocol (ICMP) echo requests to a remote host and receiving corresponding echo replies.
/// </summary>
public class Ping
{
}

/// <summary>
/// Represents a store for managing gossip members.
/// </summary>
public class GossipMemberStore : IGossipMemberStore
{
    private readonly ISystemCore _systemCore;
    private readonly ILogger _logger;
    private readonly object _memberGraphLocker = new();
    private readonly Dictionary<IPEndPoint, Peer> _peers = new();
    private readonly Ping _ping = new();

    private Dictionary<IPEndPoint, List<IServiceClient>> _serviceToServiceClients = new();

    /// <summary>
    /// Represents a store for gossip members.
    /// </summary>
    public GossipMemberStore(ISystemCore systemCore)
    {
        _systemCore = systemCore;
        using var serviceScope = systemCore.ServiceScopeFactory.CreateScope();
        _logger = serviceScope.ServiceProvider.GetService<ILogger>()?.ForContext("SourceContext", nameof(GossipMemberStore));
    }

    /// <summary>
    /// Adds or updates a gossip node in the member store based on the provided member event.
    /// </summary>
    /// <param name="memberEvent">The member event that contains information about the gossip node.</param>
    /// <returns>The <see cref="Peer"/> representing the added or updated gossip node.</returns>
    public Peer AddOrUpdateNode(MemberEvent memberEvent)
    {
        Guard.Argument(memberEvent, nameof(memberEvent)).NotNull();
        if (_systemCore.NodeId() == memberEvent.Service) return default;

        lock (_memberGraphLocker)
        {
            if (!_peers.TryGetValue(memberEvent.GossipEndPoint, out var peer))
            {
                peer = PeerFactory(memberEvent);
                _peers.Add(memberEvent.GossipEndPoint, peer);
            }
            else if (memberEvent.State == MemberState.Alive)
            {
                peer = PeerFactory(memberEvent);
                _peers[memberEvent.GossipEndPoint] = peer;
            }
            else
            {
                if (memberEvent.State == MemberState.Dead)
                {
                    _peers.Remove(memberEvent.GossipEndPoint);
                }
                else if (memberEvent.State == MemberState.Pruned)
                {
                    _peers.Remove(memberEvent.GossipEndPoint);
                }
            }
            UpdateServiceClient(memberEvent);
            return peer;
        }
    }
    
    /// <summary>
    /// Returns a new instance of the Peer class based on the provided MemberEvent object.
    /// </summary>
    /// <param name="memberEvent">The MemberEvent object used to create the Peer instance.</param>
    /// <returns>A new instance of the Peer class.</returns>
    private static Peer PeerFactory(MemberEvent memberEvent)
    {
        var peer = new Peer
        {
            IpAddress = memberEvent.IP.ToString().ToBytes(),
            NodeId = memberEvent.Service,
            TcpPort = memberEvent.GossipPort.ToBytes(),
            PublicKey = memberEvent.PublicKey[..33],
            Name = memberEvent.ServiceName
        };
        return peer;
    }

    /// <summary>
    /// Retrieve an array of peers.
    /// </summary>
    /// <returns>An array of Peer objects.</returns>
    public Peer[] GetPeers()
    {
        lock (_memberGraphLocker)
        {
            return _peers.Values.ToArray();
        }
    }

    /// <summary>
    /// Retrieves the service client for the specified service end point.
    /// </summary>
    /// <typeparam name="T">The type of the service client.</typeparam>
    /// <param name="serviceEndPoint">The IPEndPoint of the service.</param>
    /// <returns>The service client instance of type T.</returns>
    public T GetServiceClient<T>(IPEndPoint serviceEndPoint) where T : IServiceClient
    {
        if (!_serviceToServiceClients.TryGetValue(serviceEndPoint, out var serviceClients) || !serviceClients.Any())
        {
            _logger.Here().Error("No service clients available");
            return default;
        }
        var serviceClient = serviceClients.FirstOrDefault(x => x.ServiceEndPoint.Equals(serviceEndPoint));
        return (T)serviceClient;
    }

    /// <summary>
    /// Sends an asynchronous request to a service endpoint.
    /// </summary>
    /// <typeparam name="T">The type of the response object.</typeparam>
    /// <param name="serviceEndPoint">The IP endpoint of the service.</param>
    /// <param name="publicKey">The public key used for encryption.</param>
    /// <param name="value">The value to send.</param>
    /// <param name="timeMs">The timeout value in milliseconds (optional).</param>
    /// <param name="deserialize">Flag indicating whether to deserialize the response (default is true).</param>
    /// <returns>The response object of type T.</returns>
    public async Task<T> SendAsync<T>(IPEndPoint serviceEndPoint, ReadOnlyMemory<byte> publicKey,
        ReadOnlyMemory<byte> value, int timeMs = 0, bool deserialize = true)
    {
        var nngMsg = NngFactorySingleton.Instance.Factory.CreateMessage();
        try
        {
            var serviceClient = GetServiceClient<ServiceClient>(serviceEndPoint);
            if (serviceClient is null)
            {
                return default;
            }

            if (timeMs != 0)
            {
                serviceClient.Socket.SetOpt(Defines.NNG_OPT_RECVTIMEO, new nng_duration { TimeMs = timeMs });
                serviceClient.Socket.SetOpt(Defines.NNG_OPT_SENDTIMEO, new nng_duration { TimeMs = timeMs });
            }

            using var ctx = serviceClient.Socket.CreateAsyncContext(NngFactorySingleton.Instance.Factory).Unwrap();
            var cipher = _systemCore.Crypto().BoxSeal(value.Span, publicKey.Span[1..33]);

            await using var packetStream = Util.Manager.GetStream() as RecyclableMemoryStream;
            packetStream.Write(_systemCore.KeyPair.PublicKey[1..33].WrapLengthPrefix());
            packetStream.Write(cipher.WrapLengthPrefix());
            foreach (var memory in packetStream.GetReadOnlySequence()) nngMsg.Append(memory.Span);

            var nngResult = await ctx.Send(nngMsg);
            if (!nngResult.IsOk()) return default;
            if (typeof(T) == typeof(EmptyMessage)) return default;
            if (typeof(T) == typeof(Ping)) return (T)(object)_ping;
            var nngRecvMsg = nngResult.Unwrap();
            var message = await _systemCore.P2PDevice().DecryptAsync(nngRecvMsg);
            nngRecvMsg.Dispose();
            if (message.Memory.IsEmpty)
            {
                return default;
            }

            if (!deserialize)
            {
                return (T)(object)message;
            }

            using var stream = Util.Manager.GetStream(message.Memory.Span);
            var data = await MessagePackSerializer.DeserializeAsync<T>(stream);
            return data;
        }
        catch (NngException ex)
        {
            if (ex.Error == Defines.NngErrno.ECONNREFUSED) return default;
            if (ex.Error != Defines.NngErrno.EPROTO)
            {
                _logger.Here().Error("{@Message}", ex.Message);
            }
        }
        catch (Exception ex)
        {
            _logger.Here().Error("{@Message}", ex.Message);
        }
        finally
        {
            nngMsg.Dispose();
        }

        return default;
    }

    /// <summary>
    /// Sends a message to all known peers asynchronously.
    /// </summary>
    /// <param name="msg">The message to be sent.</param>
    /// <returns>A task that represents the asynchronous operation.</returns>
    public async Task SendAllAsync(ReadOnlyMemory<byte> msg)
    {
        await Parallel.ForEachAsync(_peers.Values, (knownPeer, cancellationToken) =>
        {
            try
            {
                if (cancellationToken.IsCancellationRequested) return ValueTask.CompletedTask;
                var _ = SendAsync<EmptyMessage>(
                    new IPEndPoint(IPAddress.Parse(knownPeer.IpAddress.FromBytes()), knownPeer.TcpPort.ToInt32()),
                    knownPeer.PublicKey, msg);
            }
            catch (Exception)
            {
                // Ignore
            }

            return ValueTask.CompletedTask;
        });
    }

    /// <summary>
    /// Sends the selected message asynchronously to the specified peers.
    /// </summary>
    /// <param name="msg">The message to send.</param>
    /// <param name="peers">The array of peers to send the message to.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    public async Task SendSelectedAsync(ReadOnlyMemory<byte> msg, Peer[] peers)
    {
        await Parallel.ForEachAsync(peers, (knownPeer, cancellationToken) =>
        {
            try
            {
                if (cancellationToken.IsCancellationRequested) return ValueTask.CompletedTask;
                var _ = SendAsync<EmptyMessage>(
                    new IPEndPoint(IPAddress.Parse(knownPeer.IpAddress.FromBytes()), knownPeer.TcpPort.ToInt32()),
                    knownPeer.PublicKey, msg);
            }
            catch (Exception)
            {
                // Ignore
            }

            return ValueTask.CompletedTask;
        });
    }

    /// <summary>
    /// Updates the service client based on the provided member event.
    /// </summary>
    /// <param name="memberEvent">The member event containing the information about the service client.</param>
    private void UpdateServiceClient(MemberEvent memberEvent)
    {
        IServiceClientFactory serviceClientFactory = new ServiceClientConnectFactory();
        var newServiceToServiceClients = new Dictionary<IPEndPoint, List<IServiceClient>>(_serviceToServiceClients);
        if (!newServiceToServiceClients.TryGetValue(memberEvent.GossipEndPoint, out var serviceClients))
        {
            serviceClients = new List<IServiceClient>();
        }

        List<IServiceClient> newServiceClients;
        var serviceClient = serviceClients.FirstOrDefault(s =>
            s.ServiceEndPoint.Address.Equals(memberEvent.IP) && s.ServiceEndPoint.Port == memberEvent.GossipPort);
        if (serviceClient == null && memberEvent.State == MemberState.Alive)
        {
            newServiceClients = new List<IServiceClient>(serviceClients)
                { serviceClientFactory.CreateServiceClient(new IPEndPoint(memberEvent.IP, memberEvent.GossipPort)) };
        }
        else if (serviceClient != null && memberEvent.State >= MemberState.Pruned || memberEvent.State == MemberState.Dead)
        {
            newServiceClients = new List<IServiceClient>(serviceClients);
            newServiceClients.Remove(serviceClient);
        }
        else
        {
            return;
        }

        newServiceToServiceClients[memberEvent.GossipEndPoint] = newServiceClients;
        _serviceToServiceClients = newServiceToServiceClients;
    }
}