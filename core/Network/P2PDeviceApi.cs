// Tangram by Matthew Hellyer is licensed under CC BY-NC-ND 4.0.
// To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0

using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using TangramXtgm.Extensions;
using Dawn;
using MessagePack;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IO;
using Serilog;
using TangramXtgm.Consensus.Models;
using TangramXtgm.Helper;
using TangramXtgm.Models;
using TangramXtgm.Models.Messages;

namespace TangramXtgm.Network;

/// <summary>
/// Represents an interface for a peer-to-peer device API.
/// </summary>
public interface IP2PDeviceApi
{
    IDictionary<int, Func<Parameter[], Task<ReadOnlySequence<byte>>>> Commands { get; }
}

/// <summary>
/// Class representing a P2P device API.
/// </summary>
public class P2PDeviceApi : IP2PDeviceApi
{
    private static ReadOnlySequence<byte> _updatePeersResponse;

    private readonly ISystemCore _systemCore;
    private readonly ILogger _logger;
    private readonly SemaphoreSlim _throttleOnNewBlockSemaphore = new(1);

    public P2PDeviceApi(ISystemCore systemCore)
    {
        _systemCore = systemCore;
        using var serviceScope = _systemCore.ServiceScopeFactory.CreateScope();
        _logger = serviceScope.ServiceProvider.GetService<ILogger>()
            ?.ForContext("SourceContext", nameof(P2PDeviceApi));
        Init();
    }

    public IDictionary<int, Func<Parameter[], Task<ReadOnlySequence<byte>>>> Commands { get; } =
        new Dictionary<int, Func<Parameter[], Task<ReadOnlySequence<byte>>>>();

    /// <summary>
    /// Initializes the object by serializing UpdatePeersResponse and registering a command.
    /// </summary>
    private void Init()
    {
        _updatePeersResponse = AsyncHelper.RunSync(async () => await SerializeAsync(new UpdatePeersResponse(true)));
        RegisterCommand();
    }

    /// <summary>
    /// Registers various commands and their corresponding callback methods.
    /// </summary>
    private void RegisterCommand()
    {
        Commands.Add((int)ProtocolCommand.GetLocalNode, OnGetLocalNodeAsync);
        Commands.Add((int)ProtocolCommand.GetPeers, OnGetPeersAsync);
        Commands.Add((int)ProtocolCommand.GetBlocks, OnGetBlocksAsync);
        Commands.Add((int)ProtocolCommand.GetBlock, OnGetBlockAsync);
        Commands.Add((int)ProtocolCommand.GetBlockHeight, OnGetBlockHeightAsync);
        Commands.Add((int)ProtocolCommand.GetBlockCount, OnGetBlockCountAsync);
        Commands.Add((int)ProtocolCommand.GetMemTransaction, OnGetMemoryPoolTransactionAsync);
        Commands.Add((int)ProtocolCommand.GetTransaction, OnGetTransactionAsync);
        Commands.Add((int)ProtocolCommand.Transaction, OnNewTransactionAsync);
        Commands.Add((int)ProtocolCommand.BlockGraph, OnNewBlockGraphAsync);
        Commands.Add((int)ProtocolCommand.GetPosTransaction, OnPosTransactionAsync);
        Commands.Add((int)ProtocolCommand.GetTransactionBlockIndex, OnGetTransactionBlockIndexAsync);
        Commands.Add((int)ProtocolCommand.Stake, OnStakeAsync);
        Commands.Add((int)ProtocolCommand.StakeEnabled, OnStakeEnabledAsync);
        Commands.Add((int)ProtocolCommand.GetSafeguardBlocks, OnGetSafeguardBlocksAsync);
        Commands.Add((int)ProtocolCommand.OnNewBlock, OnNewBlockAsync);
        Commands.Add((int)ProtocolCommand.OnJoin, OnJoinAsync);
        Commands.Add((int)ProtocolCommand.HandshakeInitiation, OnHandshakeInitiationAsync);
    }

    /// <summary>
    /// Handles the 'OnJoin' protocol command asynchronously.
    /// </summary>
    /// <param name="parameters">The parameters containing peer information.</param>
    /// <returns>A ReadOnlySequence<byte> representing the response.</returns>
    private async Task<ReadOnlySequence<byte>> OnJoinAsync(Parameter[] parameters)
    {
        // Ensure that the parameters are not null or empty
        Guard.Argument(parameters, nameof(parameters)).NotNull().NotEmpty();

        // Deserialize the peer information from the parameters
        var peer = MessagePackSerializer.Deserialize<Peer>(parameters[0].Value);

        // Set the received datetime for the peer
        peer.ReceivedDateTime = DateTime.UtcNow;

        // Call the 'Join' method of the PeerDiscovery component to handle the peer joining
        _systemCore.PeerDiscovery().Join(peer);

        // Serialize the response indicating successful join
        return await SerializeAsync(new JoinPeerResponse(true));
    }

    /// <summary>
    /// Handles the arrival of a new block asynchronously.
    /// </summary>
    /// <param name="parameters">An array of Parameter objects containing the block data.</param>
    /// <returns>A Task that represents the asynchronous operation. The task result contains a ReadOnlySequence<byte> object.</returns>
    private async Task<ReadOnlySequence<byte>> OnNewBlockAsync(Parameter[] parameters)
    {
        Guard.Argument(parameters, nameof(parameters)).NotNull().NotEmpty();

        await _throttleOnNewBlockSemaphore.WaitAsync();
        try
        {
            if (_systemCore.Sync().SyncRunning) return await SerializeAsync(new NewBlockResponse(true));
            var block = MessagePackSerializer.Deserialize<Models.Block>(parameters[0].Value);
            var blockCount = _systemCore.UnitOfWork().HashChainRepository.Count;

            if ((long)block.Height - (long)blockCount >= _systemCore.Node.Network.SyncTrailStop)
            {
                await _systemCore.Sync().SynchronizeAsync();
            }

            return await SerializeAsync(new NewBlockResponse(true));
        }
        finally
        {
            _throttleOnNewBlockSemaphore.Release();  // Release the semaphore once work is done
        }
    }

    /// <summary>
    /// Gets the local node asynchronously.
    /// </summary>
    /// <param name="none">No parameters needed for this method. Defaults to default value.</param>
    /// <returns>A task representing the asynchronous operation that returns a ReadOnlySequence<byte> containing the serialized local peer response.</returns>
    private async Task<ReadOnlySequence<byte>> OnGetLocalNodeAsync(Parameter[] none = default)
    {
        var localPeerResponse = _systemCore.PeerDiscovery().GetLocalNode();
        return await SerializeAsync(localPeerResponse);
    }

    /// <summary>
    /// Handles the initiation of a handshake in a communication protocol. It generates a response containing the public key of the system's key pair.
    /// </summary>
    /// <param name="none">An optional parameter, typically not used in the method logic.</param>
    /// <returns>The serialized byte sequence containing the serialized response to the handshake initiation.</returns>
    private async Task<ReadOnlySequence<byte>> OnHandshakeInitiationAsync(Parameter[] none = default)
    {       
        return await SerializeAsync(new HandshakeInitiationResponse(_systemCore.KeyPair.PublicKey));
    }

    /// <summary>
    /// Retrieves the peers asynchronously.
    /// </summary>
    /// <param name="none">Optional parameter that is not used.</param>
    /// <returns>The serialized byte sequence containing the peers.</returns>
    private async Task<ReadOnlySequence<byte>> OnGetPeersAsync(Parameter[] none = default)
    {
        return await SerializeAsync(new PeerDiscoveryResponse(_systemCore.PeerDiscovery().GetPeerStore()));
    }

    /// <summary>
    /// Retrieves a block asynchronously based on the given parameters.
    /// </summary>
    /// <param name="parameters">An array of parameters for retrieving the block.</param>
    /// <returns>The serialized version of the retrieved block as a read-only sequence of bytes.</returns>
    private async Task<ReadOnlySequence<byte>> OnGetBlockAsync(Parameter[] parameters)
    {
        Guard.Argument(parameters, nameof(parameters)).NotNull().NotEmpty();
        if (ulong.TryParse(parameters[0].Value.FromBytes(), out var blockHeight))
        {
            var blockByHeightAsync = await _systemCore.Graph().GetBlockByHeightAsync(new BlockByHeightRequest(blockHeight));
            return await SerializeAsync(blockByHeightAsync);
        }

        var block = await _systemCore.Graph().GetBlockAsync(new BlockRequest(parameters[0].Value));
        return await SerializeAsync(block);
    }

    /// <summary>
    /// Retrieves blocks asynchronously based on the given parameters.
    /// </summary>
    /// <param name="parameters">An array of parameters containing skip and take values.</param>
    /// <returns>A sequence of bytes representing the serialized blocks response.</returns>
    private async Task<ReadOnlySequence<byte>> OnGetBlocksAsync(Parameter[] parameters)
    {
        Guard.Argument(parameters, nameof(parameters)).NotNull().NotEmpty();
        var skip = Convert.ToInt32(parameters[0].Value.FromBytes());
        var take = Convert.ToInt32(parameters[1].Value.FromBytes());
        var blocksResponse = await _systemCore.Graph().GetBlocksAsync(new BlocksRequest(skip, take));
        return await SerializeAsync(blocksResponse);
    }

    /// <summary>
    /// Retrieves the block height asynchronously.
    /// </summary>
    /// <param name="none">Optional parameter that is not used in this method.</param>
    /// <returns>A <see cref="ReadOnlySequence{T}"/> containing the serialized block height response.</returns>
    private async Task<ReadOnlySequence<byte>> OnGetBlockHeightAsync(Parameter[] none = default)
    {
        return await SerializeAsync(new BlockHeightResponse(_systemCore.UnitOfWork().HashChainRepository.Height));
    }

    /// <summary>
    /// Gets the block count asynchronously.
    /// </summary>
    /// <param name="none">Optional parameters. Default value is <c>default</c>.</param>
    /// <returns>A <see cref="Task{ReadOnlySequence{byte}}"/> representing the asynchronous operation.</returns>
    private async Task<ReadOnlySequence<byte>> OnGetBlockCountAsync(Parameter[] none = default)
    {
        return await SerializeAsync(new BlockCountResponse(_systemCore.UnitOfWork().HashChainRepository.Count));
    }

    /// <summary>
    /// Retrieves a memory pool transaction asynchronously.
    /// </summary>
    /// <param name="parameters">An array of parameters.</param>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation. The task result is a <see cref="ReadOnlySequence{T}"/> of bytes.</returns>
    private async Task<ReadOnlySequence<byte>> OnGetMemoryPoolTransactionAsync(Parameter[] parameters)
    {
        Guard.Argument(parameters, nameof(parameters)).NotNull().NotEmpty();
        return await SerializeAsync(new MemoryPoolTransactionResponse(
            _systemCore.MemPool().Get(parameters[0].Value)));
    }

    /// <summary>
    /// Retrieves a transaction asynchronously.
    /// </summary>
    /// <param name="parameters">The parameters used to retrieve the transaction.</param>
    /// <returns>The retrieved transaction as a read-only sequence of bytes.</returns>
    private async Task<ReadOnlySequence<byte>> OnGetTransactionAsync(Parameter[] parameters)
    {
        Guard.Argument(parameters, nameof(parameters)).NotNull().NotEmpty();
        var transactionResponse =
            await _systemCore.Graph().GetTransactionAsync(new TransactionRequest(parameters[0].Value));
        return await SerializeAsync(transactionResponse);
    }

    /// <summary>
    /// Handles a new transaction asynchronously.
    /// </summary>
    /// <param name="parameters">The parameters required for the new transaction.</param>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation, returning a <see cref="ReadOnlySequence{T}"/> of bytes.</returns>
    private async Task<ReadOnlySequence<byte>> OnNewTransactionAsync(Parameter[] parameters)
    {
        Guard.Argument(parameters, nameof(parameters)).NotNull().NotEmpty();
        var verifyResult = await _systemCore.MemPool()
            .NewTransactionAsync(MessagePackSerializer.Deserialize<Transaction>(parameters[0].Value));
        return await SerializeAsync(new NewTransactionResponse(verifyResult == VerifyResult.Succeed));
    }

    /// <summary>
    /// Handles the event when a new block graph is received.
    /// </summary>
    /// <param name="parameters">An array of parameters.</param>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation, returning a <see cref="ReadOnlySequence{T}"/> of bytes.</returns>
    private async Task<ReadOnlySequence<byte>> OnNewBlockGraphAsync(Parameter[] parameters)
    {
        Guard.Argument(parameters, nameof(parameters)).NotNull().NotEmpty();
        await _systemCore.Graph()
            .PostAsync(MessagePackSerializer.Deserialize<BlockGraph>(parameters[0].Value));
        return await SerializeAsync(new NewBlockGraphResponse(true));
    }

    /// <summary>
    /// Retrieves the safeguard blocks asynchronously.
    /// </summary>
    /// <param name="none">Optional parameter. Defaults to null.</param>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation. The task result contains a <see cref="ReadOnlySequence{T}"/> of bytes.</returns>
    private async Task<ReadOnlySequence<byte>> OnGetSafeguardBlocksAsync(Parameter[] none = default)
    {
        const int numberOfBlocks = 147; // +- block proposal time * number of blocks
        var safeguardBlocksResponse =
            await _systemCore.Graph().GetSafeguardBlocksAsync(new SafeguardBlocksRequest(numberOfBlocks));
        return await SerializeAsync(safeguardBlocksResponse.Blocks.Any()
            ? safeguardBlocksResponse
            : safeguardBlocksResponse with { Blocks = null });
    }

    /// <summary>
    /// Processes a POS transaction asynchronously.
    /// </summary>
    /// <param name="parameters">An array of parameters for the transaction.</param>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation. The task result represents the serialized transaction response.</returns>
    private async Task<ReadOnlySequence<byte>> OnPosTransactionAsync(Parameter[] parameters)
    {
        Guard.Argument(parameters, nameof(parameters)).NotNull().NotEmpty();
        return await SerializeAsync(new PosPoolTransactionResponse(_systemCore.PPoS().Get(parameters[0].Value)));
    }

    /// <summary>
    /// Retrieves the transaction block index asynchronously.
    /// </summary>
    /// <param name="parameters">An array of <see cref="Parameter"/> objects.</param>
    /// <returns>The transaction block index as a <see cref="ReadOnlySequence{T}"/> of bytes.</returns>
    private async Task<ReadOnlySequence<byte>> OnGetTransactionBlockIndexAsync(Parameter[] parameters)
    {
        Guard.Argument(parameters, nameof(parameters)).NotNull().NotEmpty();
        var transactionBlockIndexResponse = await _systemCore.Graph()
            .GetTransactionBlockIndexAsync(new TransactionBlockIndexRequest(parameters[0].Value));
        return await SerializeAsync(transactionBlockIndexResponse);
    }

    /// <summary>
    /// Handles stake operation asynchronously.
    /// </summary>
    /// <param name="parameters">The parameters for stake operation.</param>
    /// <returns>The result of the stake operation.</returns>
    private async Task<ReadOnlySequence<byte>> OnStakeAsync(Parameter[] parameters)
    {
        Guard.Argument(parameters, nameof(parameters)).NotNull().NotEmpty();
        try
        {
            await using var stream = Util.Manager.GetStream(parameters[0].Value);
            var stakeRequest = await MessagePackSerializer.DeserializeAsync<StakeRequest>(stream);
            var packet = _systemCore.Crypto().DecryptChaCha20Poly1305(stakeRequest.Data,
                _systemCore.KeyPair.PrivateKey.FromSecureString().HexToByte(), stakeRequest.Token,
                null, stakeRequest.Nonce);
            if (packet is not null && packet.Length != 0)
            {
                var walletSession = _systemCore.WalletSession();
                var stakeCredRequest = MessagePackSerializer.Deserialize<StakeCredentialsRequest>(packet);
                var (loginSuccess, loginMessage) = await walletSession.LoginAsync(stakeCredRequest.Seed);
                if (!loginSuccess)
                    return await SerializeAsync(new StakeCredentialsResponse(loginMessage, false));

                var (setupSuccess, setupMessage) = await walletSession.InitializeWalletAsync(stakeCredRequest.Outputs);
                if (setupSuccess)
                {
                    _systemCore.Node.Staking.RewardAddress = stakeCredRequest.RewardAddress.FromBytes();
                    _systemCore.Node.Staking.Enabled = true;
                    return await SerializeAsync(new StakeCredentialsResponse(setupMessage, true));
                }
            }
            else
            {
                return await SerializeAsync(new StakeCredentialsResponse("Unable to decrypt message", false));
            }
        }
        catch (Exception ex)
        {
            _logger.Here().Error("{@Message}", ex.Message);
        }

        return await SerializeAsync(new StakeCredentialsResponse("Unable to setup staking", false));
    }

    /// <summary>
    /// Handles stake enabled async operation.
    /// </summary>
    /// <param name="parameters">The parameters for the operation.</param>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation that returns a <see cref="ReadOnlySequence{T}"/> of bytes.</returns>
    private async Task<ReadOnlySequence<byte>> OnStakeEnabledAsync(Parameter[] parameters)
    {
        Guard.Argument(parameters, nameof(parameters)).NotNull().NotEmpty();
        try
        {
            await using var stream = Util.Manager.GetStream(parameters[0].Value);
            var stakeRequest = await MessagePackSerializer.DeserializeAsync<StakeRequest>(stream);
            var packet = _systemCore.Crypto().DecryptChaCha20Poly1305(stakeRequest.Data,
                _systemCore.KeyPair.PrivateKey.FromSecureString().HexToByte(), stakeRequest.Token,
                null, stakeRequest.Nonce);
            if (packet is null)
                return await SerializeAsync(new StakeCredentialsResponse("Unable to decrypt message", false));

            return await SerializeAsync(new StakeCredentialsResponse(
                _systemCore.Node.Staking.Enabled ? "Staking enabled" : "Staking not enabled", true));
        }
        catch (Exception ex)
        {
            _logger.Here().Error("{@Message}", ex.Message);
        }

        return await SerializeAsync(new StakeCredentialsResponse("Unable to setup staking", false));
    }

    /// <summary>
    /// Serializes a value of type T asynchronously.
    /// </summary>
    /// <typeparam name="T">The type of the value to be serialized.</typeparam>
    /// <param name="value">The value to be serialized.</param>
    /// <returns>A task that represents the asynchronous operation. The task result contains the serialized value as a read-only sequence of bytes.</returns>
    public static async Task<ReadOnlySequence<byte>> SerializeAsync<T>(T value)
    {
        await using var stream =
            Util.Manager.GetStream(MessagePackSerializer.Serialize(value)) as
                RecyclableMemoryStream;
        return stream.GetReadOnlySequence();
    }
}