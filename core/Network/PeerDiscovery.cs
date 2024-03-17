// Tangram by Matthew Hellyer is licensed under CC BY-NC-ND 4.0.
// To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Reactive.Linq;
using System.Threading.Tasks;
using MessagePack;
using TangramXtgm.Extensions;
using NBitcoin;
using Serilog;
using TangramXtgm.Helper;
using TangramXtgm.Models;
using TangramXtgm.Models.Messages;
using TangramXtgm.Persistence;
using nng;
using nng.Native;
using System.Net.Http;
using Microsoft.IO;
using Nerdbank.Streams;
using Spectre.Console;
using System.Buffers;

namespace TangramXtgm.Network;

/// <summary>
/// Represents a peer discovery interface.
/// </summary>
public interface IPeerDiscovery
{
    Peer[] GetPeerStore();
    LocalNode GetLocalNode();
    int Count();
    void SetPeerCooldown(PeerCooldown peer);
    Task<ulong> NetworkBlockCountAsync();
    Task<ulong> PeerBlockCountAsync(Peer peer);
    Task<LocalNode> PeerInfoAsync(Peer peer);
    T GetServiceClient<T>(IPEndPoint serviceEndPoint) where T : IServiceClient;
    void Join(Peer peer);
    Task InitAsync();
    Task<T> SendAsync<T>(IPEndPoint serviceEndPoint, ReadOnlyMemory<byte> publicKey, ReadOnlyMemory<byte> value, int timeMs = 0, bool deserialize = true);
    Task SendAllAsync(ReadOnlyMemory<byte> msg);
    Task SendSelectedAsync(ReadOnlyMemory<byte> msg, Peer[] peers);
    Task<HandshakeInitiationResponse> SendHandshakeInitiationAsync(IPEndPoint serviceEndPoint, int timeMs = 0);
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
/// 
/// </summary>
public class ClientPubKey
{
    public string PublicKey { get; set; }
}

/// <summary>
/// The PeerDiscovery class is responsible for discovering and managing peer nodes in a network.
/// </summary>
public sealed class PeerDiscovery : IDisposable, IPeerDiscovery
{

    private int _protocolPeriodMilliseconds = 500;
    private int _ackTimeoutMilliseconds = 250;
    private int _deadTimeoutMilliseconds = 5000;
    public int ProtocolPeriodMilliseconds
    {
        get => _protocolPeriodMilliseconds;
        set
        {
            _protocolPeriodMilliseconds = value;
            _ackTimeoutMilliseconds = value / 2;
            _deadTimeoutMilliseconds = value * 10;
        }
    }

    public int AckTimeoutMilliseconds => _ackTimeoutMilliseconds;
    public int NumberOfIndirectEndpoints { get; set; } = 10;
    public int FanoutFactor { get; set; } = 10;
    public int DeadTimeoutMilliseconds => _deadTimeoutMilliseconds;
    public int DeadCoolOffMilliseconds { get; set; } = 300000;
    public int PruneTimeoutMilliseconds { get; set; } = 600000;

    private const int CooldownTimeoutFromMinutes = 10;
    private readonly Caching<Peer> _peerCache = new();
    private readonly Caching<PeerCooldown> _peerCooldownCaching = new();
    private readonly ISystemCore _systemCore;
    private readonly ILogger _logger;
    private readonly Ping _ping = new();
    private readonly object _locker = new();
    private readonly Random _rand = new();

    private IDisposable _coolDownDisposable;
    private LocalNode _localNode;
    private Peer _localPeer;
    private bool _disposed;
   
    private Dictionary<IPEndPoint, List<IServiceClient>> _serviceToServiceClients = new();
    private volatile Dictionary<IPEndPoint, DateTime> _awaitingAcks = new();

    private DateTime _lastProtocolPeriod = DateTime.UtcNow;

    /// <summary>
    /// Initializes a new instance of the <see cref="PeerDiscovery"/> class.
    /// </summary>
    /// <param name="systemCore">The core system providing essential functionality.</param>
    /// <param name="logger">The logger for recording log messages.</param>
    public PeerDiscovery(ISystemCore systemCore, ILogger logger)
    {
        _systemCore = systemCore;
        _logger = logger;
    }

    /// <summary>
    /// Asynchronous method responsible for initializing the system.
    /// </summary>
    /// <returns>An asynchronous Task.</returns>
    public async Task InitAsync()
    {
        // Create a LocalNode instance with local system information
        _localNode = new LocalNode
        {
            IpAddress = _systemCore.Node.EndPoint.Address.ToString().ToBytes(),
            NodeId = _systemCore.NodeId(),
            TcpPort = _systemCore.Node.Network.P2P.TcpPort.ToBytes(),
            WsPort = _systemCore.Node.Network.P2P.WsPort.ToBytes(),
            HttpPort = _systemCore.Node.Network.HttpPort.ToBytes(),
            HttpsPort = _systemCore.Node.Network.HttpsPort.ToBytes(),
            Name = _systemCore.Node.Name.ToBytes(),
            PublicKey = _systemCore.KeyPair.PublicKey,
            Version = Util.GetAssemblyVersionString().ToBytes()
        };

        // Create a LocalPeer instance with local system information
        _localPeer = new Peer
        {
            IpAddress = _localNode.IpAddress,
            NodeId = (uint)_localNode.NodeId,
            TcpPort = _systemCore.Node.Network.P2P.TcpPort.ToBytes(),
            PublicKey = _systemCore.KeyPair.PublicKey,
            Name = _systemCore.Node.Name.ToBytes(),
            Version = Util.GetAssemblyVersionString().ToBytes()
        };

        // Bootstrap the system by discovering and connecting to initial seed peers
        await BootstrapperAsync().ConfigureAwait(false);

        // Start the gossip pump asynchronously
        GossipPumpAsync().SafeFireAndForget();

        // Initiate handling of peer cooldown
        HandlePeerCooldown();

        // Start the dead peer handler asynchronously
        DeadPeerHandlerAsync().SafeFireAndForget();

        // Start the network partition guard asynchronously
        NetworkPartitionGaurdAsync().SafeFireAndForget();
    }

    /// <summary>
    /// Joins the network by adding a peer to the local peer cache.
    /// </summary>
    /// <param name="peer">The peer to be added to the network.</param>
    public void Join(Peer peer)
    {
        // Check if the given peer's endpoint is marked as a seed in the peer cache
        var endPoint = IsEndPointSeed(ref peer);

        // Add or update the peer in the local peer cache
        _peerCache.AddOrUpdate(PeerKey(endPoint), peer);

        // Update the service client associated with the peer
        UpdateServiceClient(peer);
    }

    /// <summary>
    /// Returns the key for a given Peer object.
    /// </summary>
    /// <param name="ipEndPoint"></param>
    /// <returns>The key for the Peer.</returns>
    private static byte[] PeerKey(IPEndPoint ipEndPoint)
    {
        return $"{ipEndPoint.Address}:{ipEndPoint.Port}".ToBytes();
    }

    /// <summary>
    /// Retrieves the block count from each known peer in parallel, and returns the maximum block count.
    /// </summary>
    /// <returns>The maximum block count from the known peers, or 0 if there are no responses.</returns>
    public async Task<ulong> NetworkBlockCountAsync()
    {
        var blockHeightResponses = new List<BlockHeightResponse>();
        await Parallel.ForEachAsync(GetPeerStore(), async (knownPeer, cancellationToken) =>
        {
            var msg = MessagePackSerializer.Serialize(new Parameter[]
            {
                new() {ProtocolCommand = ProtocolCommand.GetBlockCount}
            }, cancellationToken: cancellationToken);
            var blockCountResponse = await SendAsync<BlockHeightResponse>(
                    new IPEndPoint(IPAddress.Parse(knownPeer.IpAddress.FromBytes()), knownPeer.TcpPort.ToInt32()),
                    knownPeer.PublicKey, msg);
            if (blockCountResponse is not null)
                blockHeightResponses.Add(blockCountResponse);
        });
        return blockHeightResponses.Any() ? blockHeightResponses.Max(x => x.Count) : 0;
    }

    /// <summary>
    /// Retrieves the block count from a peer asynchronously.
    /// </summary>
    /// <param name="peer">The Peer object representing the peer from which to retrieve the block count.</param>
    /// <returns>The block count retrieved from the peer.</returns>
    public async Task<ulong> PeerBlockCountAsync(Peer peer)
    {
        var blockCountResponse = await SendAsync<BlockHeightResponse>(
                new IPEndPoint(IPAddress.Parse(peer.IpAddress.FromBytes()), peer.TcpPort.ToInt32()),
                peer.PublicKey, MessagePackSerializer.Serialize(new Parameter[]
                {
                    new() { ProtocolCommand = ProtocolCommand.GetBlockCount }
                }));

        return blockCountResponse?.Count ?? 0;
    }

    /// <summary>
    /// Retrieves information about a peer node in the network.
    /// </summary>
    /// <param name="peer">The peer node to retrieve information about.</param>
    /// <returns>A <see cref="LocalNode"/> object containing information about the peer node.</returns>
    public async Task<LocalNode> PeerInfoAsync(Peer peer)
    {
        var peerInfoResponse = await SendAsync<LocalNode>(
                new IPEndPoint(IPAddress.Parse(peer.IpAddress.FromBytes()), peer.TcpPort.ToInt32()),
                peer.PublicKey, MessagePackSerializer.Serialize(new Parameter[]
                {
                    new() { ProtocolCommand = ProtocolCommand.GetLocalNode }
                }));

        return peerInfoResponse;
    }

    /// <summary>
    /// Returns the number of peers in the GossipMemberStore.
    /// </summary>
    /// <returns>The number of peers.</returns>
    public int Count()
    {
        return _peerCache.Count;
    }

    /// <summary>
    /// Retrieves the current list of gossip members from the GossipMemberStore, excluding any cooled-down peers.
    /// </summary>
    /// <returns>An array of Peer objects representing the active gossip members.</returns>
    public Peer[] GetPeerStore()
    {
        var peers = _peerCache.GetItems();
        return peers.Where(node => _peerCooldownCaching.GetItems().All(coolDown =>
            !coolDown.IpAddress.Xor(node.IpAddress.AsSpan()) && coolDown.PeerState != PeerState.OrphanBlock)).ToArray();
    }

    /// <summary>
    /// Retrieves the local node.
    /// </summary>
    /// <returns>A LocalNode object representing the local node.</returns>
    public LocalNode GetLocalNode()
    {
        return _localNode;
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
    /// Sends a handshake initiation message to a service endpoint and waits for a response.
    /// </summary>
    /// <param name="serviceEndPoint">The service endpoint to send the message to.</param>  
    /// <param name="timeMs">Timeout duration in milliseconds (0 for no timeout).</param>
    /// <returns>
    /// A <see cref="HandshakeInitiationResponse"/> received as a response to the handshake initiation.
    /// </returns>
    public async Task<HandshakeInitiationResponse> SendHandshakeInitiationAsync(IPEndPoint serviceEndPoint, int timeMs = 0)
    {
        // Create an NNG message to hold the handshake initiation data
        var nngMsg = NngFactorySingleton.Instance.Factory.CreateMessage();
        try
        {
            ServiceClientConnectFactory serviceClientConnectFactory = new();

            // Creates the service client associated with the specified endpoint
            ServiceClient serviceClient = (ServiceClient)serviceClientConnectFactory.CreateServiceClient(serviceEndPoint);                      
            if (serviceClient is null)
            {
                return new HandshakeInitiationResponse(Array.Empty<byte>()); ; // Return default if the service client is not available
            }

            // Configure timeout settings if a timeout duration is provided
            if (timeMs != 0)
            {
                serviceClient.Socket.SetOpt(Defines.NNG_OPT_RECVTIMEO, new nng_duration { TimeMs = timeMs });
                serviceClient.Socket.SetOpt(Defines.NNG_OPT_SENDTIMEO, new nng_duration { TimeMs = timeMs });
            }

            // Create an asynchronous context for sending the handshake initiation message
            using var ctx = serviceClient.Socket.CreateAsyncContext(NngFactorySingleton.Instance.Factory).Unwrap();

            // Prepare the handshake initiation message.
            var msg = ProtocolCommand.HandshakeInitiation.ToString().ToBytes();
            nngMsg.Append(msg);

            // Send the handshake initiation message
            var nngResult = await ctx.Send(nngMsg);
            if (!nngResult.IsOk()) return new HandshakeInitiationResponse(Array.Empty<byte>());

            // Dispose of the sent message as it's no longer needed
            var nngRecvMsg = nngResult.Unwrap();
           
            // Receive the response message and deserialize it into a HandshakeInitiationResponse object
            using var stream = Util.Manager.GetStream(nngRecvMsg.AsSpan());
            var data = await MessagePackSerializer.DeserializeAsync<HandshakeInitiationResponse>(stream);

            return data;
        }
        catch (NngException ex)
        {
            // Handle NNG-specific exceptions
            if (ex.Error == Defines.NngErrno.ECONNREFUSED) return default; // Connection refused, return default
            if (ex.Error != Defines.NngErrno.EPROTO)
            {
                _logger.Here().Error("{@Message}", ex.Message); // Log other NNG errors
            }
        }
        catch (Exception ex)
        {
            // Handle general exceptions
            _logger.Here().Error("{@Message}", ex.Message);
        }
        finally
        {
            // Dispose of the NNG message
            nngMsg.Dispose();
        }

        return new HandshakeInitiationResponse(Array.Empty<byte>());
    }

    /// <summary>
    /// Sends a message to all known peers asynchronously.
    /// </summary>
    /// <param name="msg">The message to be sent.</param>
    /// <returns>A task that represents the asynchronous operation.</returns>
    public async Task SendAllAsync(ReadOnlyMemory<byte> msg)
    {
        await Parallel.ForEachAsync(_peerCache.GetItems(), (knownPeer, cancellationToken) =>
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
    /// Returns the encryption key for the given client ID and IP address.
    /// </summary>
    /// <param name="clientId">The unique identifier of the client.</param>
    /// <param name="ipAddress">The IP address of the client.</param>
    /// <returns>The encryption key as a byte array.</returns>
    private static byte[] GetKey(ulong clientId, byte[] ipAddress)
    {
        return StoreDb.Key(clientId.ToString(), ipAddress);
    }

    /// <summary>
    /// Checks if a given Peer's endpoint is marked as a seed in the peer cache.
    /// Updates the Peer's IsSeed property accordingly.
    /// </summary>
    /// <param name="peer">The Peer to check and update.</param>
    /// <returns>The IPEndPoint representing the peer's endpoint.</returns>
    private IPEndPoint IsEndPointSeed(ref Peer peer)
    {
        // Create an IPEndPoint based on the peer's IP address and TCP port
        var endPoint = Util.GetIpEndPoint($"{peer.IpAddress.FromBytes()}:{peer.TcpPort.ToInt32()}");

        // Check if the endpoint is marked as a seed in the peer cache
        if (_peerCache.TryGet(PeerKey(endPoint), out var peerCache))
        {
            // If the endpoint is a seed, update the IsSeed property of the current peer
            if (peerCache.IsSeed)
            {
                peer.IsSeed = true;
            }
        }

        // Return the IPEndPoint representing the peer's endpoint
        return endPoint;
    }


    /// <summary>
    /// Asynchronous method responsible for bootstrapping the system by discovering and connecting to initial seed peers.
    /// </summary>
    /// <returns>An asynchronous Task.</returns>
    private async Task BootstrapperAsync()
    {
        // Check if there are no seed nodes specified
        if (_systemCore.Node.Network.SeedList == null || _systemCore.Node.Network.SeedList.Count == 0)
        {
            _logger.Here().Information("No seeds to bootstrap off");
            return;
        }

        _logger.Here().Information("Bootstrapping off seeds");

        // Continue bootstrapping until peers are discovered
        while (IsPeersEmpty())
        {
            // Iterate through each seed in the seed list
            foreach (var seed in _systemCore.Node.Network.SeedList)
            {
                // Split the seed into host and port
                var endpoint = seed.Split(':');                
                var destinationEndPoint = new IPEndPoint(IPAddress.Parse(endpoint[0]), Convert.ToInt32(endpoint[1]));

                // Check if a peer with the same IP address exists in the peer cache
                if (_peerCache.GetItems().FirstOrDefault(x => x.IpAddress.Xor(endpoint[0].ToBytes())).IsDefault())
                {
                    try
                    {
                        // Send a handshake initiation message to the specified host's endpoint
                        var handshakeInitiationResponse = await SendHandshakeInitiationAsync(destinationEndPoint);

                        // Check if the handshake initiation was successful (public key received)
                        if (handshakeInitiationResponse.PublicKey.Length == 0)
                        {
                            // If the public key is empty, skip the current iteration
                            continue;
                        }

                        // Create a Peer object with the extracted information
                        var peer = new Peer
                        {
                            PeerState = PeerState.Alive,
                            IpAddress = endpoint[0].ToBytes(),                                                       
                            PublicKey = handshakeInitiationResponse.PublicKey,
                            TcpPort = endpoint[1].ToBytes(),                            
                            IsSeed = true
                        };

                        // Update the service client associated with the peer
                        UpdateServiceClient(peer);
                      
                        // Send a message to the destination endpoint to request the local node information
                        var localNode = await SendAsync<LocalNode>(
                            destinationEndPoint,
                            handshakeInitiationResponse.PublicKey,
                            MessagePackSerializer.Serialize(new Parameter[]
                            {
                                new() { ProtocolCommand = ProtocolCommand.GetLocalNode }
                            })
                        );

                        // Check if the localNode information is not available
                        if (localNode == null)
                        {
                            // If localNode is null, skip the current iteration
                            continue;
                        }

                        // Create a Peer object with the extracted information
                        peer = new Peer
                        {
                            PeerState = PeerState.Alive,
                            IpAddress = localNode.IpAddress,
                            Name = localNode.Name,
                            NodeId = (uint)localNode.NodeId,
                            PublicKey = localNode.PublicKey,
                            TcpPort = localNode.TcpPort,
                            Version = localNode.Version,
                            IsSeed = true
                        };

                        // Send a join request to the discovered peer
                        var joinPeerResponse = await SendAsync<JoinPeerResponse>(
                            new IPEndPoint(IPAddress.Parse(peer.IpAddress.FromBytes()), peer.TcpPort.ToInt32()),
                            peer.PublicKey, MessagePackSerializer.Serialize(new Parameter[]
                                {
                                new() { Value = _localPeer.Serialize(), ProtocolCommand = ProtocolCommand.OnJoin },
                                }
                            ));

                        // If the join request is successful, add the peer to the peer cache
                        if (joinPeerResponse != null && joinPeerResponse.Ok)
                        {                           
                            _peerCache.Add(PeerKey(destinationEndPoint), peer);
                        }
                    }
                    catch (HttpRequestException ex)
                    {
                        // Log errors related to HttpClient requests
                        _logger.Here().Error("{@Message}", ex.Message);
                    }
                    catch (Exception ex)
                    {
                        // Log other exceptions that may occur during the bootstrapping process
                        _logger.Here().Error("{@Message}", ex.Message);
                    }
                }
            }

            // Ping a random seed node and wait for the protocol period before the next iteration
            await PingRandomSeedAsync().ConfigureAwait(false);
            await Task.Delay(ProtocolPeriodMilliseconds).ConfigureAwait(false);
        }

        _logger.Here().Information("Finished bootstrapping");
    }

    /// <summary>
    /// Asynchronous method responsible for running a gossip protocol pump.
    /// </summary>
    private async Task GossipPumpAsync()
    {
        // Continue the loop until the application is stopping
        while (!_systemCore.ApplicationLifetime.ApplicationStopping.IsCancellationRequested)
        {
            try
            {
                // Get random gossip endpoints based on the specified fanout factor
                var gossipEndPoints = GetRandomEndPoints(FanoutFactor).ToArray();

                // Initialize an array to hold tasks for gossiping to different endpoints
                var gossipTasks = new Task[gossipEndPoints.Length];

                // Iterate through each endpoint and create a task for gossiping
                for (int i = 0; i < gossipEndPoints.Length; i++)
                {
                    gossipTasks[i] = GossipAsync(gossipEndPoints[i]);
                }

                // Wait for all gossip tasks to complete before moving forward
                await Task.WhenAll(gossipTasks).ConfigureAwait(false);

                // Introduce a delay before the next iteration to control the protocol period
                await WaitForProtocolPeriodAsync().ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                // Log any exceptions that occur during the gossiping process
                _logger.Here().Error("{@Message}", ex.Message);
            }
        }
    }

    /// <summary>
    /// Asynchronous method responsible for initiating the gossip protocol with a specific endpoint.
    /// </summary>
    /// <param name="endPoint">The IPEndPoint to gossip with.</param>
    /// <returns>An asynchronous Task.</returns>
    private async Task GossipAsync(IPEndPoint endPoint)
    {
        try
        {
            // Add the endpoint to the list of awaiting acknowledgments
            AddAwaitingAck(endPoint);

            // Send a Ping message asynchronously to the specified endpoint
            await PingAsync(endPoint).ConfigureAwait(false);

            // Introduce a delay to wait for acknowledgment
            await Task.Delay(AckTimeoutMilliseconds).ConfigureAwait(false);

            // Check if the acknowledgment was not received within the timeout
            if (WasNotAcked(endPoint))
            {
                // If not acknowledged, perform a second round of gossiping
                // Get a random set of indirect endpoints
                var indirectEndpoints = GetRandomEndPoints(NumberOfIndirectEndpoints);

                // Request Ping from the indirect endpoints
                await RequestPingAsync(indirectEndpoints).ConfigureAwait(false);

                // Ping the original endpoint again
                await PingAsync(endPoint).ConfigureAwait(false);

                // Introduce another delay for acknowledgment in the second round
                await Task.Delay(AckTimeoutMilliseconds).ConfigureAwait(false);
            }
        }
        catch (Exception ex)
        {
            // Log any exceptions that occur during the gossiping process
            _logger.Here().Error("{@Message}", ex.Message);
        }
    }

    /// <summary>
    /// Updates the state of a peer in the peer cache.
    /// </summary>
    /// <param name="endPoint">The IPEndPoint identifying the peer.</param>
    /// <param name="peerState">The new state of the peer.</param>
    private void UpdatePeerState(IPEndPoint endPoint, PeerState peerState)
    {
        // Acquire a lock to ensure thread safety when updating the peer cache
        lock (_locker)
        {
            // Try to get the existing peer information from the peer cache
            if (_peerCache.TryGet(PeerKey(endPoint), out var peerCache))
            {
                // Update the peer state with the new value
                peerCache.PeerState = peerState;

                // Add or update the peer information in the cache
                _peerCache.AddOrUpdate(PeerKey(endPoint), peerCache);
            }
            // If the peer does not exist in the cache, it might be a new peer, and no update is needed
        }
    }

    /// <summary>
    /// Checks if the peer cache is empty.
    /// </summary>
    /// <returns>True if the peer cache is empty, otherwise false.</returns>
    private bool IsPeersEmpty()
    {
        // Check if the count of peers in the peer cache is equal to 0
        return _peerCache.Count == 0;
    }

    /// <summary>
    /// Asynchronous method responsible for guarding against network partitions by periodically pinging random seed nodes.
    /// </summary>
    private async Task NetworkPartitionGaurdAsync()
    {
        // Check if the seed list is null or empty, if so, return without further action
        if (_systemCore.Node.Network.SeedList == null || _systemCore.Node.Network.SeedList.Count == 0)
        {
            return;
        }

        try
        {
            // Continue the loop until the application is stopping
            while (!_systemCore.ApplicationLifetime.ApplicationStopping.IsCancellationRequested)
            {
                // Calculate the delay based on the current number of peers in the peer cache
                var n = 0;
                lock (_locker)
                {
                    n = _peerCache.Count * 1000;
                }

                // Introduce a delay, ensuring it is at least 60 seconds or proportional to the number of peers
                await Task.Delay(Math.Max(60000, n)).ConfigureAwait(false);

                // Ping a random seed node to check network connectivity
                await PingRandomSeedAsync().ConfigureAwait(false);
            }
        }
        catch (Exception ex)
        {
            // Log any exceptions that occur during the network partition guard process
            _logger.Here().Error("{@Message}", ex.Message);
        }
    }

    /// <summary>
    /// Asynchronous method responsible for waiting until the next protocol period.
    /// </summary>
    /// <returns>An asynchronous Task.</returns>
    private async Task WaitForProtocolPeriodAsync()
    {
        // Calculate the time remaining until the next protocol period
        var syncTime = Math.Max(ProtocolPeriodMilliseconds - (int)(DateTime.UtcNow - _lastProtocolPeriod).TotalMilliseconds, 0);

        // Introduce a delay to wait until the next protocol period
        await Task.Delay(syncTime).ConfigureAwait(false);

        // Update the last protocol period timestamp to the current time
        _lastProtocolPeriod = DateTime.UtcNow;
    }

    /// <summary>
    /// Asynchronous method responsible for pinging a random seed node from the peer cache.
    /// </summary>
    /// <returns>An asynchronous Task.</returns>
    private async Task PingRandomSeedAsync()
    {
        try
        {
            // Retrieve all seed nodes from the peer cache
            var seeds = _peerCache.GetItems().Where(x => x.IsSeed == true).ToArray();

            // If there are no seed nodes, return without further action
            if (!seeds.Any()) return;

            // Generate a random index to select a seed node from the array
            var i = _rand.Next(0, seeds.Length);

            // Create an IPEndPoint using the IP address and TCP port of the selected seed node
            var endPoint = Util.GetIpEndPoint($"{seeds[i].IpAddress.FromBytes()}:{seeds[i].TcpPort.ToInt32()}");

            // Ping the selected seed node asynchronously
            await PingAsync(endPoint).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            // Log any exceptions that occur during the ping to a random seed node
            _logger.Here().Error("{@Message}", ex.Message);
        }
    }

    /// <summary>
    /// Asynchronous method responsible for initiating a Ping message to a specified destination endpoint.
    /// </summary>
    /// <param name="destinationEndPoint">The IPEndPoint representing the destination for the Ping message.</param>
    /// <returns>An asynchronous Task.</returns>
    private async Task PingAsync(IPEndPoint destinationEndPoint)
    {
        // Use SendMessageAsync to send a Ping message to the specified destination endpoint
        await SendMessageAsync(ProtocolCommand.GetPeers, destinationEndPoint).ConfigureAwait(false);
    }

    /// <summary>
    /// Asynchronous method responsible for requesting Ping messages from a collection of indirect endpoints.
    /// </summary>
    /// <param name="indirectEndPoints">A collection of IPEndPoints representing the indirect endpoints to request Pings from.</param>
    /// <returns>An asynchronous Task.</returns>
    private async Task RequestPingAsync(IEnumerable<IPEndPoint> indirectEndPoints)
    {
        // Iterate through each indirect endpoint in the collection
        foreach (var indirectEndPoint in indirectEndPoints)
        {
            // Use SendMessageAsync to send a Ping message to the current indirect endpoint
            await SendMessageAsync(ProtocolCommand.GetPeers, indirectEndPoint).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Asynchronous method responsible for sending a message to a specified destination endpoint using the specified protocol command.
    /// </summary>
    /// <param name="protocolCommand">The ProtocolCommand indicating the type of message to send.</param>
    /// <param name="destinationEndPoint">The IPEndPoint representing the destination for the message.</param>
    /// <returns>An asynchronous Task.</returns>
    private async Task SendMessageAsync(ProtocolCommand protocolCommand, IPEndPoint destinationEndPoint)
    {
        // Create a sequence to hold the serialized peer information
        var sequence = new Sequence<byte>();

        // Get the list of peers from the peer cache, including the local peer
        IList<Peer> discoveryStore = _peerCache.GetItems().ToList();
        discoveryStore.Add(_localPeer);

        // Populate the sequence with the read-only representation of the peer information
        ReadOnlyPeerSequence(ref discoveryStore, ref sequence);

        try
        {
            // Check if the destination endpoint exists in the peer cache
            if (_peerCache.TryGet(PeerKey(destinationEndPoint), out var peerCache))
            {
                // Send a message to the destination endpoint and await the response
                var peerDiscoveryResponse = await SendAsync<PeerDiscoveryResponse>(destinationEndPoint, peerCache.PublicKey,
                    MessagePackSerializer.Serialize(new Parameter[]
                    {
                    new() { Value = sequence.AsReadOnlySequence.ToArray(), ProtocolCommand = protocolCommand },
                    }
                    ), 500);

                // Process the response and update the peer cache accordingly
                if (peerDiscoveryResponse != null && peerDiscoveryResponse.Peers != null)
                {
                    foreach (var peer in peerDiscoveryResponse.Peers)
                    {
                        // Skip updating the local peer in the cache
                        if (_systemCore.NodeId() == peer.NodeId) continue;

                        // Update the service client associated with the peer
                        UpdateServiceClient(peer);

                        // Check if the peer has a specific endpoint as a seed
                        var p = peer;
                        var endPoint = IsEndPointSeed(ref p);

                        // Add or update the peer information in the cache
                        _peerCache.AddOrUpdate(PeerKey(endPoint), p);
                    }

                    // Update the received date and peer state in the cache
                    peerCache.ReceivedDateTime = DateTime.UtcNow;
                    UpdatePeerState(destinationEndPoint, PeerState.Alive);
                }
                else
                {
                    // If no response or no peers in the response, mark the destination peer as dead
                    UpdatePeerState(destinationEndPoint, PeerState.Dead);
                }

                // Update the list of awaiting acknowledgment peers
                UpdateAwaitingAckPeers();
            }
        }
        catch (Exception ex)
        {
            // Log any exceptions that occur during the message sending process
            _logger.Here().Error("{@Message}", ex.Message);
        }
    }

    /// <summary>
    /// Populates a MessagePack sequence with the read-only representation of a list of peers.
    /// </summary>
    /// <param name="peers">The list of peers to be serialized.</param>
    /// <param name="sequence">The MessagePack sequence to be populated.</param>
    private static void ReadOnlyPeerSequence(ref IList<Peer> peers, ref Sequence<byte> sequence)
    {
        // Create a MessagePack writer using the provided sequence
        var writer = new MessagePackWriter(sequence);

        // Write the array header indicating the number of peers in the list
        writer.WriteArrayHeader(peers.Count);

        // Serialize each peer in the list and write it to the sequence
        foreach (var peer in peers)
        {
            // Serialize the peer and write it to the sequence
            MessagePackSerializer.Serialize(ref writer, peer);

            // Flush the writer to ensure the data is written to the sequence
            writer.Flush();
        }
    }

    /// <summary>
    /// Retrieves a specified number of random IPEndPoints from the peer cache, excluding the provided direct gossip endpoint.
    /// </summary>
    /// <param name="numberOfEndPoints">The number of random IPEndPoints to retrieve.</param>
    /// <param name="directGossipEndPoint">The IPEndPoint to exclude from the result.</param>
    /// <returns>An IEnumerable of IPEndPoints representing the randomly selected endpoints.</returns>
    private IEnumerable<IPEndPoint> GetRandomEndPoints(int numberOfEndPoints)
    {
        // Retrieve all peers from the peer cache
        var peers = _peerCache.GetItems();

        // Generate a random starting index
        var randomIndex = _rand.Next(0, peers.Length);

        // If there are no peers, return an empty collection
        if (peers.Length == 0)
        {
            return Enumerable.Empty<IPEndPoint>();
        }

        // Generate a sequence of random indices based on the starting index and the number of endpoints
        return Enumerable.Range(randomIndex, numberOfEndPoints)
            .Select(ri => ri % peers.Length) // Wrap around to ensure valid indices
            .Select(i => peers[i]) // Select peers based on the random indices           
            .Select(m => new IPEndPoint(IPAddress.Parse(m.IpAddress.FromBytes()), m.TcpPort.ToInt32())) // Convert to IPEndPoint
            .Distinct() // Ensure uniqueness
            .Take(numberOfEndPoints); // Take the specified number of endpoints
    }


    /// <summary>
    /// Sets the cooldown for a peer.
    /// </summary>
    /// <param name="peer">The PeerCooldown object representing the peer.</param>
    public void SetPeerCooldown(PeerCooldown peer)
    {
        if (!_peerCooldownCaching.TryGet(GetKey(peer.NodeId, peer.IpAddress), out _))
        {
            _peerCooldownCaching.AddOrUpdate(StoreDb.Key(peer.NodeId.ToString(), peer.IpAddress), peer);
        }
    }

    /// <summary>
    /// Updates the list of peers awaiting acknowledgment based on their current PeerState.
    /// </summary>
    private void UpdateAwaitingAckPeers()
    {
        // Retrieve all peers from the peer cache
        var peers = _peerCache.GetItems();

        // Iterate through each peer in the cache
        foreach (var peer in peers)
        {
            // Create an IPEndPoint based on the peer's IP address and TCP port
            var endPoint = Util.GetIpEndPoint($"{peer.IpAddress.FromBytes()}:{peer.TcpPort.ToInt32()}");

            // Check the current PeerState of the peer
            if (peer.PeerState == PeerState.Alive)
            {
                // If the peer is alive, remove it from the list of peers awaiting acknowledgment
                RemoveAwaitingAck(endPoint);
            }
            else
            {
                // If the peer is not alive, add it to the list of peers awaiting acknowledgment
                AddAwaitingAck(endPoint);
            }
        }
    }

    /// <summary>
    /// Asynchronous method responsible for handling dead peers, including pruning and updating peer states.
    /// </summary>
    private async Task DeadPeerHandlerAsync()
    {
        // Continue processing while the application is running
        while (!_systemCore.ApplicationLifetime.ApplicationStopping.IsCancellationRequested)
        {
            try
            {
                // Use a lock to ensure thread safety when accessing and modifying shared resources
                lock (_locker)
                {
                    // Iterate through each awaiting acknowledgment entry
                    foreach (var awaitingAck in _awaitingAcks.ToArray())
                    {
                        // Check if the awaiting acknowledgment entry has exceeded the prune timeout
                        if (DateTime.UtcNow > awaitingAck.Value.AddMilliseconds(PruneTimeoutMilliseconds))
                        {
                            // Attempt to get the peer information from the peer cache
                            if (_peerCache.TryGet(PeerKey(awaitingAck.Key), out var peer) &&
                                (peer.PeerState == PeerState.Dead || peer.PeerState == PeerState.Left))
                            {
                                // Update the peer state to Pruned and update the service client
                                UpdatePeerState(awaitingAck.Key, PeerState.Pruned);
                                UpdateServiceClient(peer);

                                // Remove the peer from the peer cache
                                _peerCache.Remove(PeerKey(awaitingAck.Key));
                            }

                            // Remove the awaiting acknowledgment entry
                            _awaitingAcks.Remove(awaitingAck.Key);
                        }
                        // Check if the awaiting acknowledgment entry has exceeded the dead timeout
                        else if (DateTime.UtcNow > awaitingAck.Value.AddMilliseconds(DeadTimeoutMilliseconds))
                        {
                            // Update the peer state to Dead
                            UpdatePeerState(awaitingAck.Key, PeerState.Dead);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                // Log any exceptions that occur during the dead peer handling process
                _logger.Here().Error("{@Message}", ex.Message);
            }

            // Introduce a delay before the next iteration
            await Task.Delay(1000).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Handles the cooldown for peers.
    /// </summary>
    private void HandlePeerCooldown()
    {
        _coolDownDisposable = Observable.Interval(TimeSpan.FromMinutes(CooldownTimeoutFromMinutes)).Subscribe(_ =>
        {
            if (_systemCore.ApplicationLifetime.ApplicationStopping.IsCancellationRequested) return;
            try
            {
                var removePeerCooldownBeforeTimestamp = Util.GetUtcNow().AddMinutes(-CooldownTimeoutFromMinutes).ToUnixTimestamp();
                var removePeersCooldown = AsyncHelper.RunSync(async delegate
                {
                    return await _peerCooldownCaching.WhereAsync(x =>
                        new ValueTask<bool>(x.Value.Timestamp < removePeerCooldownBeforeTimestamp));
                });
                foreach (var (key, _) in removePeersCooldown)
                    _peerCooldownCaching.Remove(key);
            }
            catch (TaskCanceledException)
            {
                // Ignore
            }
            catch (Exception ex)
            {
                _logger.Here().Error("{@Message}", ex.Message);
            }
        });
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="gossipEndPoint"></param>
    private void AddAwaitingAck(IPEndPoint gossipEndPoint)
    {
        lock (_locker)
        {
            if (!_awaitingAcks.ContainsKey(gossipEndPoint))
            {
                _awaitingAcks.Add(gossipEndPoint, DateTime.UtcNow);
            }
        }
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="gossipEndPoint"></param>
    /// <returns></returns>
    private bool WasNotAcked(IPEndPoint gossipEndPoint)
    {
        var wasNotAcked = false;
        lock (_locker)
        {
            wasNotAcked = _awaitingAcks.ContainsKey(gossipEndPoint);
        }

        return wasNotAcked;
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="gossipEndPoint"></param>
    private void RemoveAwaitingAck(IPEndPoint gossipEndPoint)
    {
        lock (_locker)
        {
            if (_awaitingAcks.ContainsKey(gossipEndPoint))
            {
                _awaitingAcks.Remove(gossipEndPoint);
            }
        }
    }

    /// <summary>
    /// Checks if the provided byte array represents an accepted address.
    /// </summary>
    /// <param name="value">The byte array that represents an IP address.</param>
    /// <returns>True if the address is accepted, False otherwise.</returns>
    private static bool IsAcceptedAddress(byte[] value)
    {
        try
        {
            if (IPAddress.TryParse(value.FromBytes(), out var address))
            {
                return address.ToString() != "127.0.0.1" && address.ToString() != "0.0.0.0";
            }
        }
        catch (Exception)
        {
            // Ignore
        }

        return false;
    }

    /// <summary>
    /// Updates the service client based on the provided member event.
    /// </summary>
    /// <param name="memberEvent">The member event containing the information about the service client.</param>
    private void UpdateServiceClient(Peer peer)
    {
        IServiceClientFactory serviceClientFactory = new ServiceClientConnectFactory();
        var newServiceToServiceClients = new Dictionary<IPEndPoint, List<IServiceClient>>(_serviceToServiceClients);
        var endPoint = Util.GetIpEndPoint($"{peer.IpAddress.FromBytes()}:{peer.TcpPort.ToInt32()}");

        if (!newServiceToServiceClients.TryGetValue(endPoint, out var serviceClients))
        {
            serviceClients = new List<IServiceClient>();
        }

        List<IServiceClient> newServiceClients;
        var serviceClient = serviceClients.FirstOrDefault(s =>
            s.ServiceEndPoint.Address.Equals(endPoint.Address) && s.ServiceEndPoint.Port == endPoint.Port);
        if (serviceClient == null && peer.PeerState == PeerState.Alive)
        {
            newServiceClients = new List<IServiceClient>(serviceClients)
                { serviceClientFactory.CreateServiceClient(endPoint) };
        }
        else if (serviceClient != null && peer.PeerState >= PeerState.Pruned)
        {
            newServiceClients = new List<IServiceClient>(serviceClients);
            newServiceClients.Remove(serviceClient);
        }
        else
        {
            return;
        }

        newServiceToServiceClients[endPoint] = newServiceClients;
        _serviceToServiceClients = newServiceToServiceClients;
    }

    /// <summary>
    /// Disposes the resources used by the object.
    /// </summary>
    /// <param name="disposing">True to dispose managed resources, false to only dispose unmanaged resources.</param>
    private void Dispose(bool disposing)
    {
        if (_disposed)
        {
            return;
        }

        if (disposing)
        {           
            _coolDownDisposable?.Dispose();
        }

        _disposed = true;
    }

    /// <summary>
    /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
    /// </summary>
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }
}