// Tangram by Matthew Hellyer is licensed under CC BY-NC-ND 4.0.
// To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0

using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
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
/// 
/// </summary>
public interface IP2PDeviceApi
{
    IDictionary<int, Func<Parameter[], Task<ReadOnlySequence<byte>>>> Commands { get; }
}

/// <summary>
/// 
/// </summary>
public class P2PDeviceApi : IP2PDeviceApi
{
    private static ReadOnlySequence<byte> _updatePeersResponse;

    private readonly ISystemCore _systemCore;
    private readonly ILogger _logger;

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
    /// </summary>
    private void Init()
    {
        _updatePeersResponse = AsyncHelper.RunSync(async () => await SerializeAsync(new UpdatePeersResponse(true)));
        RegisterCommand();
    }

    /// <summary>
    /// </summary>
    private void RegisterCommand()
    {
        Commands.Add((int)ProtocolCommand.GetLocalNode, OnGetLocalNodeAsync);
        Commands.Add((int)ProtocolCommand.GetPeers, OnGetPeersAsync);
        Commands.Add((int)ProtocolCommand.GetBlocks, OnGetBlocksAsync);
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
    }

    /// <summary>
    /// </summary>
    /// <returns></returns>
    private async Task<ReadOnlySequence<byte>> OnGetLocalNodeAsync(Parameter[] none = default)
    {
        var localPeerResponse = _systemCore.PeerDiscovery().GetLocalNode();
        return await SerializeAsync(localPeerResponse);
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="none"></param>
    /// <returns></returns>
    private async Task<ReadOnlySequence<byte>> OnGetPeersAsync(Parameter[] none = default)
    {
        return await SerializeAsync(_systemCore.PeerDiscovery().GetGossipMemberStore());
    }

    /// <summary>
    /// </summary>
    /// <param name="parameters"></param>
    /// <returns></returns>
    private async Task<ReadOnlySequence<byte>> OnGetBlocksAsync(Parameter[] parameters)
    {
        Guard.Argument(parameters, nameof(parameters)).NotNull().NotEmpty();
        var skip = Convert.ToInt32(parameters[0].Value.FromBytes());
        var take = Convert.ToInt32(parameters[1].Value.FromBytes());
        var blocksResponse = await _systemCore.Graph().GetBlocksAsync(new BlocksRequest(skip, take));
        return await SerializeAsync(blocksResponse);
    }

    /// <summary>
    /// </summary>
    private async Task<ReadOnlySequence<byte>> OnGetBlockHeightAsync(Parameter[] none = default)
    {
        return await SerializeAsync(new BlockHeightResponse(_systemCore.UnitOfWork().HashChainRepository.Height));
    }

    /// <summary>
    /// </summary>
    private async Task<ReadOnlySequence<byte>> OnGetBlockCountAsync(Parameter[] none = default)
    {
        return await SerializeAsync(new BlockCountResponse(_systemCore.UnitOfWork().HashChainRepository.Count));
    }

    /// <summary>
    /// </summary>
    /// <param name="parameters"></param>
    /// <returns></returns>
    private async Task<ReadOnlySequence<byte>> OnGetMemoryPoolTransactionAsync(Parameter[] parameters)
    {
        Guard.Argument(parameters, nameof(parameters)).NotNull().NotEmpty();
        return await SerializeAsync(new MemoryPoolTransactionResponse(
            _systemCore.MemPool().Get(parameters[0].Value)));
    }

    /// <summary>
    /// </summary>
    /// <param name="parameters"></param>
    /// <returns></returns>
    private async Task<ReadOnlySequence<byte>> OnGetTransactionAsync(Parameter[] parameters)
    {
        Guard.Argument(parameters, nameof(parameters)).NotNull().NotEmpty();
        var transactionResponse =
            await _systemCore.Graph().GetTransactionAsync(new TransactionRequest(parameters[0].Value));
        return await SerializeAsync(transactionResponse);
    }

    /// <summary>
    /// </summary>
    /// <param name="parameters"></param>
    /// <returns></returns>
    private async Task<ReadOnlySequence<byte>> OnNewTransactionAsync(Parameter[] parameters)
    {
        Guard.Argument(parameters, nameof(parameters)).NotNull().NotEmpty();
        var verifyResult = await _systemCore.MemPool()
            .NewTransactionAsync(MessagePackSerializer.Deserialize<Transaction>(parameters[0].Value));
        return await SerializeAsync(new NewTransactionResponse(verifyResult == VerifyResult.Succeed));
    }

    /// <summary>
    /// </summary>
    /// <param name="parameters"></param>
    /// <returns></returns>
    private async Task<ReadOnlySequence<byte>> OnNewBlockGraphAsync(Parameter[] parameters)
    {
        Guard.Argument(parameters, nameof(parameters)).NotNull().NotEmpty();
        await _systemCore.Graph()
            .PostAsync(MessagePackSerializer.Deserialize<BlockGraph>(parameters[0].Value));
        return await SerializeAsync(new NewBlockGraphResponse(true));
    }

    /// <summary>
    /// </summary>
    /// <param name="none"></param>
    /// <returns></returns>
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
    /// </summary>
    /// <param name="parameters"></param>
    /// <returns></returns>
    private async Task<ReadOnlySequence<byte>> OnPosTransactionAsync(Parameter[] parameters)
    {
        Guard.Argument(parameters, nameof(parameters)).NotNull().NotEmpty();
        return await SerializeAsync(new PosPoolTransactionResponse(_systemCore.PPoS().Get(parameters[0].Value)));
    }

    /// <summary>
    /// </summary>
    /// <param name="parameters"></param>
    /// <returns></returns>
    private async Task<ReadOnlySequence<byte>> OnGetTransactionBlockIndexAsync(Parameter[] parameters)
    {
        Guard.Argument(parameters, nameof(parameters)).NotNull().NotEmpty();
        var transactionBlockIndexResponse = await _systemCore.Graph()
            .GetTransactionBlockIndexAsync(new TransactionBlockIndexRequest(parameters[0].Value));
        return await SerializeAsync(transactionBlockIndexResponse);
    }

    /// <summary>
    /// </summary>
    /// <param name="parameters"></param>
    /// <returns></returns>
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
            if (packet is null)
                return await SerializeAsync(new StakeCredentialsResponse("Unable to decrypt message", false));

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
        catch (Exception ex)
        {
            _logger.Here().Error("{@Message}", ex.Message);
        }

        return await SerializeAsync(new StakeCredentialsResponse("Unable to setup staking", false));
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="parameters"></param>
    /// <returns></returns>
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
    /// 
    /// </summary>
    /// <param name="value"></param>
    /// <typeparam name="T"></typeparam>
    /// <returns></returns>
    public static async Task<ReadOnlySequence<byte>> SerializeAsync<T>(T value)
    {
        await using var stream =
            Util.Manager.GetStream(MessagePackSerializer.Serialize(value)) as
                RecyclableMemoryStream;
        return stream.GetReadOnlySequence();
    }
}