// Tangram by Matthew Hellyer is licensed under CC BY-NC-ND 4.0.
// To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0

using System;
using System.Security;
using TangramXtgm.Extensions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Serilog;
using TangramXtgm.Cryptography;
using TangramXtgm.Helper;
using TangramXtgm.Ledger;
using TangramXtgm.Models;
using TangramXtgm.Network;
using TangramXtgm.Persistence;
using TangramXtgm.Wallet;

namespace TangramXtgm;

/// <summary>
/// Represents the core system interface.
/// </summary>
public interface ISystemCore
{
    IHostApplicationLifetime ApplicationLifetime { get; }
    IServiceScopeFactory ServiceScopeFactory { get; }
    Node Node { get; }
    KeyPair KeyPair { get; }
    IUnitOfWork UnitOfWork();
    IPeerDiscovery PeerDiscovery();
    IGraph Graph();
    IPPoS PPoS();
    IValidator Validator();
    ISync Sync();
    IMemoryPool MemPool();
    INodeWallet Wallet();
    IWalletSession WalletSession();
    IBroadcast Broadcast();
    ICrypto Crypto();
    IP2PDevice P2PDevice();
    IP2PDeviceApi P2PDeviceApi();
    Cache<object> Cache();
    IGossipMemberStore GossipMemberStore();
    uint NodeId();

}

/// <summary>
/// Represents a key pair consisting of a private key and a public key.
/// </summary>
public record KeyPair
{
    public SecureString PrivateKey { get; init; }

    /// <summary>
    /// </summary>
    public byte[] PublicKey { get; init; }
}

/// <summary>
/// Represents a cache implementation that can store objects of type T.
/// </summary>
/// <typeparam name="T">The type of objects to be stored in the cache.</typeparam>
public class Cache<T> : Caching<T> where T : class
{
}

/// <summary>
/// System core class that provides access to various system components and services.
/// </summary>
public class SystemCore : ISystemCore
{
    private readonly ILogger _logger;
    private readonly Cache<object> _cache = new();

    private uint _nodeId;

    private IUnitOfWork _unitOfWork;
    private IPeerDiscovery _peerDiscovery;
    private IGraph _graph;
    private IPPoS _poS;
    private ISync _sync;
    private IMemoryPool _memoryPool;
    private IWalletSession _walletSession;
    private IP2PDevice _p2PDevice;
    private IP2PDeviceApi _p2PDeviceApi;
    private ICrypto _crypto;
    private IGossipMemberStore _gossipMemberStore;


    /// <summary>
    /// Represents a system core.
    /// </summary>
    /// <param name="applicationLifetime">The host application lifetime object.</param>
    /// <param name="serviceScopeFactory">The service scope factory.</param>
    /// <param name="node">The node object.</param>
    /// <param name="logger">The logger object.</param>
    public SystemCore(IHostApplicationLifetime applicationLifetime,
        IServiceScopeFactory serviceScopeFactory, Node node, ILogger logger)
    {
        ApplicationLifetime = applicationLifetime;
        ServiceScopeFactory = serviceScopeFactory;
        Node = node;
        _logger = logger;
        Init();
    }

    /// <summary>
    /// Returns the ID of the node.
    /// </summary>
    /// <returns>The ID of the node.</returns>
    public uint NodeId()
    {
        return _nodeId;
    }

    /// <summary>
    /// Represents a KeyPair object.
    /// </summary>
    public KeyPair KeyPair { get; private set; }

    /// <summary>
    /// Gets the application lifetime which provides access to the application's lifetime events and allows registering for callbacks that are triggered during the application's lifetime
    /// .
    /// </summary>
    public IHostApplicationLifetime ApplicationLifetime { get; }

    /// <summary>
    /// Gets the service scope factory used to create service scopes for resolving dependencies.
    /// </summary>
    public IServiceScopeFactory ServiceScopeFactory { get; }

    /// <summary>
    /// Represents a node in a data structure.
    /// </summary>
    public Node Node { get; }

    /// <summary>
    /// Retrieves the GossipMemberStore instance. If it is null, it calls the GetGossipMemberStore method to get a new instance and assigns it to the _gossipMemberStore field.
    /// </summary>
    /// <returns>The GossipMemberStore instance.</returns>
    public IGossipMemberStore GossipMemberStore()
    {
        _gossipMemberStore ??= GetGossipMemberStore();
        return _gossipMemberStore;
    }

    /// <summary>
    /// Creates or retrieves the existing unit of work.
    /// </summary>
    /// <returns>
    /// An instance of the <see cref="IUnitOfWork"/> interface representing the unit of work.
    /// </returns>
    public IUnitOfWork UnitOfWork()
    {
        _unitOfWork ??= GetUnitOfWork();
        return _unitOfWork;
    }

    /// <summary>
    /// Retrieves the instance of IPeerDiscovery and if not found, initializes and returns it.
    /// </summary>
    /// <returns>The instance of IPeerDiscovery.</returns>
    public IPeerDiscovery PeerDiscovery()
    {
        _peerDiscovery ??= GetPeerDiscovery();
        return _peerDiscovery;
    }

    /// <summary>
    /// Returns an instance of the graph.
    /// </summary>
    /// <returns>The graph.</returns>
    public IGraph Graph()
    {
        _graph ??= GetGraph();
        return _graph;
    }

    /// <summary>
    /// Retrieves the PPoS object.
    /// </summary>
    /// <returns>
    /// The PPoS object if it has been previously initialized,
    /// otherwise a newly created PPoS object.
    /// </returns>
    public IPPoS PPoS()
    {
        _poS ??= GetPPoS();
        return _poS;
    }

    /// <summary>
    /// The Crypto method returns an instance of the ICrypto interface.
    /// </summary>
    /// <returns>
    /// Returns an instance of the ICrypto interface.
    /// </returns>
    public ICrypto Crypto()
    {
        _crypto ??= GetCrypto();
        return _crypto;
    }

    /// <summary>
    /// Returns an instance of the IValidator interface.
    /// </summary>
    /// <returns>An instance of the IValidator interface, or null if an exception occurs.</returns>
    public IValidator Validator()
    {
        try
        {
            using var scope = ServiceScopeFactory.CreateAsyncScope();
            var validator = scope.ServiceProvider.GetRequiredService<IValidator>();
            return validator;
        }
        catch (Exception ex)
        {
            _logger.Here().Error("{@Message}", ex.Message);
        }

        return null;
    }

    /// <summary>
    /// Retrieves the sync object and initializes it if necessary.
    /// </summary>
    /// <returns>
    /// A reference to the ISync object.
    /// </returns>
    public ISync Sync()
    {
        _sync ??= GetSync();
        return _sync;
    }

    /// <summary>
    /// Retrieves the memory pool instance.
    /// </summary>
    /// <returns>The memory pool instance of type IMemoryPool.</returns>
    public IMemoryPool MemPool()
    {
        _memoryPool ??= GetMemPool();
        return _memoryPool;
    }

    /// <summary>
    /// Returns the P2P device for communication.
    /// </summary>
    /// <returns>The P2P device.<returns>
    public IP2PDevice P2PDevice()
    {
        _p2PDevice ??= GetP2PDevice();
        return _p2PDevice;
    }

    /// <summary>
    /// Retrieves the P2PDeviceApi.
    /// </summary>
    /// <returns>
    /// The P2PDeviceApi interface.
    /// </returns>
    public IP2PDeviceApi P2PDeviceApi()
    {
        _p2PDeviceApi ??= GetP2PDeviceApi();
        return _p2PDeviceApi;
    }

    /// <summary>
    /// Retrieves the instance of the INodeWallet interface.
    /// </summary>
    /// <returns>The instance of the INodeWallet interface.</returns>
    public INodeWallet Wallet()
    {
        try
        {
            using var scope = ServiceScopeFactory.CreateAsyncScope();
            var wallet = scope.ServiceProvider.GetRequiredService<INodeWallet>();
            return wallet;
        }
        catch (Exception ex)
        {
            _logger.Here().Error("{@Message}", ex.Message);
        }

        return null;
    }

    /// <summary>
    /// Gets the wallet session. If a session is already created, returns the existing session.
    /// Otherwise, creates a new session and returns it.
    /// </summary>
    /// <returns>The wallet session.</returns>
    public IWalletSession WalletSession()
    {
        _walletSession ??= GetWalletSession();
        return _walletSession;
    }

    /// <summary>
    /// Retrieves an instance of the IBroadcast service from the service provider within a scope.
    /// </summary>
    /// <remarks>
    /// This method creates a new service scope using the ServiceScopeFactory. Within this scope, it resolves an instance of the IBroadcast service from the service provider using the Get
    /// RequiredService method.
    /// </remarks>
    /// <exception cref="Exception">Thrown when there is an error while resolving the IBroadcast service.</exception>
    /// <returns>An instance of the IBroadcast service if resolved successfully; otherwise, null.</returns>
    public IBroadcast Broadcast()
    {
        try
        {
            using var scope = ServiceScopeFactory.CreateAsyncScope();
            var broadcast = scope.ServiceProvider.GetRequiredService<IBroadcast>();
            return broadcast;
        }
        catch (Exception ex)
        {
            _logger.Here().Error("{@Message}", ex.Message);
        }

        return null;
    }

    /// <summary>
    /// Returns an instance of ICrypto obtained from the DI container. </summary> <returns>
    /// An instance of ICrypto if it is registered in the DI container.
    /// If an exception occurs during the retrieval process, null will be returned and an error will be logged. </returns>
    /// /
    private ICrypto GetCrypto()
    {
        try
        {
            using var scope = ServiceScopeFactory.CreateAsyncScope();
            var crypto = scope.ServiceProvider.GetRequiredService<ICrypto>();
            return crypto;
        }
        catch (Exception ex)
        {
            _logger.Here().Error("{@Message}", ex.Message);
        }

        return null;
    }

    /// <summary>
    /// Retrieves the instance of the IP2PDevice service for Peer-to-Peer communication.
    /// </summary>
    /// <returns>
    /// An instance of the IP2PDevice service, or null if an error occurred while retrieving the service.
    /// </returns>
    private IP2PDevice GetP2PDevice()
    {
        try
        {
            using var scope = ServiceScopeFactory.CreateAsyncScope();
            var p2PDevice = scope.ServiceProvider.GetRequiredService<IP2PDevice>();
            return p2PDevice;
        }
        catch (Exception ex)
        {
            _logger.Here().Error("{@Message}", ex.Message);
        }

        return null;
    }

    /// <summary>
    /// Gets an instance of the IP2PDeviceApi.
    /// </summary>
    /// <returns>An instance of IP2PDeviceApi if it is successfully retrieved, otherwise null.</returns>
    private IP2PDeviceApi GetP2PDeviceApi()
    {
        try
        {
            using var scope = ServiceScopeFactory.CreateAsyncScope();
            var p2PDeviceApi = scope.ServiceProvider.GetRequiredService<IP2PDeviceApi>();
            return p2PDeviceApi;
        }
        catch (Exception ex)
        {
            _logger.Here().Error("{@Message}", ex.Message);
        }

        return null;
    }

    /// <summary>
    /// Retrieves the cache object.
    /// </summary>
    /// <returns>A Cache object.</returns>
    public Cache<object> Cache()
    {
        return _cache;
    }

    /// <summary>
    /// Initializes the object by generating cryptographic keys and setting the node identifier.
    /// </summary>
    private void Init()
    {
        _crypto = GetCrypto();
        var keyPair = AsyncHelper.RunSync(() => _crypto.GetOrUpsertKeyNameAsync(Node.Network.SigningKeyRingName));
        KeyPair = new KeyPair
        {
            PrivateKey = keyPair.PrivateKey.ByteToHex().ToSecureString(),
            PublicKey = keyPair.PublicKey
        };
        keyPair.PrivateKey.Destroy();
        _nodeId = keyPair.PublicKey.ToHashIdentifier();
    }

    /// <summary>
    /// Retrieves an instance of the unit of work for accessing the data layer.
    /// </summary>
    /// <returns>An instance of the <see cref="IUnitOfWork"/> interface.</returns>
    private IUnitOfWork GetUnitOfWork()
    {
        try
        {
            using var scope = ServiceScopeFactory.CreateScope();
            var unitOfWork = scope.ServiceProvider.GetRequiredService<IUnitOfWork>();
            return unitOfWork;
        }
        catch (Exception ex)
        {
            _logger.Here().Error("{@Message}", ex.Message);
        }

        return null;
    }

    /// <summary>
    /// Retrieves the instance of IGossipMemberStore by creating a new service scope
    /// and resolving the service from the service provider.
    /// </summary>
    /// <returns>The instance of IGossipMemberStore if found, otherwise null.</returns>
    private IGossipMemberStore GetGossipMemberStore()
    {
        try
        {
            using var scope = ServiceScopeFactory.CreateScope();
            var gossipMemberStore = scope.ServiceProvider.GetRequiredService<IGossipMemberStore>();
            return gossipMemberStore;
        }
        catch (Exception ex)
        {
            _logger.Here().Error("{@Message}", ex.Message);
        }

        return null;
    }

    /// <summary>
    /// GetPeerDiscovery is a private method that returns an instance of IPeerDiscovery.
    /// </summary>
    /// <returns>An instance of IPeerDiscovery if successful, otherwise null.</returns>
    private IPeerDiscovery GetPeerDiscovery()
    {
        try
        {
            using var scope = ServiceScopeFactory.CreateScope();
            var peerDiscovery = scope.ServiceProvider.GetRequiredService<IPeerDiscovery>();
            return peerDiscovery;
        }
        catch (Exception ex)
        {
            _logger.Here().Error("{@Message}", ex.Message);
        }

        return null;
    }

    /// <summary>
    /// Retrieves the instance of the IPPoS service using the current service scope.
    /// </summary>
    /// <returns>
    /// The instance of the IPPoS service, or null if an exception occurred.
    /// </returns>
    private IPPoS GetPPoS()
    {
        try
        {
            using var scope = ServiceScopeFactory.CreateAsyncScope();
            var pPoS = scope.ServiceProvider.GetRequiredService<IPPoS>();
            return pPoS;
        }
        catch (Exception ex)
        {
            _logger.Here().Error("{@Message}", ex.Message);
        }

        return null;
    }

    /// <summary>
    /// Retrieves an instance of the IGraph interface by creating a service scope and resolving the IGraph service provider.
    /// </summary>
    /// <returns>An instance of the IGraph interface if successful; otherwise null.</returns>
    private IGraph GetGraph()
    {
        try
        {
            using var scope = ServiceScopeFactory.CreateScope();
            var graph = scope.ServiceProvider.GetRequiredService<IGraph>();
            return graph;
        }
        catch (Exception ex)
        {
            _logger.Here().Error("{@Message}", ex.Message);
        }

        return null;
    }

    /// <summary>
    /// Retrieves a reference to the ISync service for performing synchronization tasks.
    /// </summary>
    /// <returns>An instance of ISync if it can be resolved from the service provider, otherwise null.</returns>
    private ISync GetSync()
    {
        try
        {
            using var scope = ServiceScopeFactory.CreateAsyncScope();
            var sync = scope.ServiceProvider.GetRequiredService<ISync>();
            return sync;
        }
        catch (Exception ex)
        {
            _logger.Here().Error("{@Message}", ex.Message);
        }

        return null;
    }

    /// <summary>
    /// Returns the Memory Pool used for allocating and managing memory resources.
    /// </summary>
    /// <returns>The Memory Pool instance.</returns>
    private IMemoryPool GetMemPool()
    {
        try
        {
            using var scope = ServiceScopeFactory.CreateAsyncScope();
            var memoryPool = scope.ServiceProvider.GetRequiredService<IMemoryPool>();
            return memoryPool;
        }
        catch (Exception ex)
        {
            _logger.Here().Error("{@Message}", ex.Message);
        }

        return null;
    }

    /// <summary>
    /// Gets the currently active wallet session.
    /// </summary>
    /// <returns>The currently active wallet session, or null if an error occurred.</returns>
    private IWalletSession GetWalletSession()
    {
        try
        {
            using var scope = ServiceScopeFactory.CreateAsyncScope();
            var walletSession = scope.ServiceProvider.GetRequiredService<IWalletSession>();
            return walletSession;
        }
        catch (Exception ex)
        {
            _logger.Here().Error("{@Message}", ex.Message);
        }

        return null;
    }
}