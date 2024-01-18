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
using TangramXtgm.Network.Mesh;
using TangramXtgm.Persistence;

namespace TangramXtgm.Network;

/// <summary>
/// Represents a peer discovery interface.
/// </summary>
public interface IPeerDiscovery
{
    /// <summary>
    /// </summary>
    /// <returns></returns>
    Peer[] GetGossipMemberStore();

    /// <summary>
    /// </summary>
    /// <returns></returns>
    LocalNode GetLocalNode();

    /// <summary>
    /// </summary>
    /// <returns></returns>
    int Count();

    void SetPeerCooldown(PeerCooldown peer);

    Task<ulong> NetworkBlockCountAsync();

    Task<ulong> PeerBlockCountAsync(Peer peer);
}

/// <summary>
/// The PeerDiscovery class is responsible for discovering and managing peer nodes in a network.
/// </summary>
public sealed class PeerDiscovery : IDisposable, IPeerDiscovery
{
    private const int CooldownTimeoutFromMinutes = 10;
    private readonly Caching<PeerCooldown> _peerCooldownCaching = new();
    private readonly ISystemCore _systemCore;
    private readonly ILogger _logger;
    private IDisposable _coolDownDisposable;
    private LocalNode _localNode;
    private bool _disposed;
    private Gossiper _gossiper;

    private readonly IMemberListener _memberListener;

    /// <summary>
    /// Represents a class that handles peer discovery for the system.
    /// </summary>
    /// <param name="systemCore">The <see cref="ISystemCore"/> instance that provides core system functionality.</param>
    /// <param name="memberListener">The <see cref="IMemberListener"/> instance that handles listening for new members.</param>
    /// <param name="logger">The <see cref="ILogger"/> instance that handles logging.</param>
    /// <remarks>
    /// The <see cref="PeerDiscovery"/> class initializes a new instance with the provided system core, member listener, and logger.
    /// </remarks>
    public PeerDiscovery(ISystemCore systemCore, IMemberListener memberListener, ILogger logger)
    {
        _systemCore = systemCore;
        _logger = logger;
        _memberListener = memberListener;
        Init();
    }

    /// <summary>
    /// Retrieves the block count from each known peer in parallel, and returns the maximum block count.
    /// </summary>
    /// <returns>The maximum block count from the known peers, or 0 if there are no responses.</returns>
    public async Task<ulong> NetworkBlockCountAsync()
    {
        var blockHeightResponses = new List<BlockHeightResponse>();
        await Parallel.ForEachAsync(GetGossipMemberStore(), async (knownPeer, cancellationToken) =>
        {
            var msg = MessagePackSerializer.Serialize(new Parameter[]
            {
                new() {ProtocolCommand = ProtocolCommand.GetBlockCount}
            }, cancellationToken: cancellationToken);
            var blockCountResponse = await _systemCore.GossipMemberStore()
                .SendAsync<BlockHeightResponse>(
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
        var blockCountResponse = await _systemCore.GossipMemberStore()
            .SendAsync<BlockHeightResponse>(
                new IPEndPoint(IPAddress.Parse(peer.IpAddress.FromBytes()), peer.TcpPort.ToInt32()),
                peer.PublicKey, MessagePackSerializer.Serialize(new Parameter[]
                {
                    new() { ProtocolCommand = ProtocolCommand.GetBlockCount }
                }));

        return blockCountResponse?.Count ?? 0;
    }

    /// <summary>
    /// Returns the number of peers in the GossipMemberStore.
    /// </summary>
    /// <returns>The number of peers.</returns>
    public int Count()
    {
        return _systemCore.GossipMemberStore().GetPeers().Length;
    }

    /// <summary>
    /// Retrieves the current list of gossip members from the GossipMemberStore, excluding any cooled-down peers.
    /// </summary>
    /// <returns>An array of Peer objects representing the active gossip members.</returns>
    public Peer[] GetGossipMemberStore()
    {
        var peers = _systemCore.GossipMemberStore().GetPeers();
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
    /// This method initializes the local node by setting its properties and starting the gossiper.
    /// </summary>
    private void Init()
    {
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
        var endPoints = new IPEndPoint[_systemCore.Node.Network.SeedList.Count];
        foreach (var seedNode in _systemCore.Node.Network.SeedList.WithIndex())
        {
            var endpoint = Util.GetIpEndPoint(seedNode.item);
            endPoints[seedNode.index] = endpoint;
        }
        StartGossiperAsync(endPoints).ConfigureAwait(false);
        HandlePeerCooldown();
    }

    /// <summary>
    /// Starts the gossiper asynchronously.
    /// </summary>
    /// <param name="seeds">The seed IP endpoints.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    private async Task StartGossiperAsync(IPEndPoint[] seeds)
    {
        var logger = Util.CreateLogger<PeerDiscovery>();
        var options = new GossiperOptions
        {
            SeedMembers = seeds,
            MemberListeners = new List<IMemberListener> { _memberListener }
        };
        var listenPort = (ushort)_systemCore.Node.Network.P2P.TcpPort;
        _gossiper = new Gossiper(listenPort, _systemCore.NodeId(), _systemCore.Node.Name.ToBytes(), Util.GetAssemblyVersionBytes(),
            _systemCore.KeyPair.PublicKey, listenPort, options,
            _systemCore.ApplicationLifetime.ApplicationStopping, logger);
        await _gossiper.StartAsync();
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
            _gossiper?.Dispose();
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