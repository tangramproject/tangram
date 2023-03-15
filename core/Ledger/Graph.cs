// Tangram by Matthew Hellyer is licensed under CC BY-NC-ND 4.0.
// To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0

using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Reactive;
using System.Reactive.Concurrency;
using System.Reactive.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Threading.Tasks.Dataflow;
using Blake3;
using TangramXtgm.Extensions;
using Dawn;
using MessagePack;
using Microsoft.IO;
using NBitcoin;
using Serilog;
using Spectre.Console;
using TangramXtgm.Consensus;
using TangramXtgm.Consensus.Models;
using TangramXtgm.Helper;
using TangramXtgm.Models;
using TangramXtgm.Models.Messages;
using TangramXtgm.Network;
using TangramXtgm.Persistence;
using Block = TangramXtgm.Models.Block;

namespace TangramXtgm.Ledger;

/// <summary>
/// </summary>
public interface IGraph
{
    Task<TransactionBlockIndexResponse> GetTransactionBlockIndexAsync(TransactionBlockIndexRequest transactionIndexRequest);
    Task<BlockResponse> GetTransactionBlockAsync(TransactionIdRequest transactionIndexRequest);
    Task<TransactionResponse> GetTransactionAsync(TransactionRequest transactionRequest);
    Task<Block> GetPreviousBlockAsync();
    Task<SafeguardBlocksResponse> GetSafeguardBlocksAsync(SafeguardBlocksRequest safeguardBlocksRequest);
    Task<SaveBlockResponse> SaveBlockAsync(SaveBlockRequest saveBlockRequest);
    Task<BlocksResponse> GetBlocksAsync(BlocksRequest blocksRequest);
    Task PostAsync(BlockGraph blockGraph);
    Task<BlockResponse> GetBlockAsync(BlockRequest blockRequest);
    Task<BlockResponse> GetBlockByHeightAsync(BlockByHeightRequest blockByHeightRequest);
    Task<VerifyResult> BlockHeightExistsAsync(BlockHeightExistsRequest blockHeightExistsRequest);
    Task<VerifyResult> BlockExistsAsync(BlockExistsRequest blockExistsRequest);
    byte[] HashTransactions(HashTransactionsRequest hashTransactionsRequest);
    Task<bool> BlockCountSynchronizedAsync();
}

/// <summary>
/// </summary>
internal record SeenBlockGraph
{
    public long Timestamp { get; } = Helper.Util.GetAdjustedTimeAsUnixTimestamp();
    public ulong Round { get; init; }
    public byte[] Hash { get; init; }
    public byte[] Key { get; init; }
}

/// <summary>
/// </summary>
public sealed class Graph : ReceivedActor<BlockGraph>, IGraph, IDisposable
{
    private class BlockGraphEventArgs : EventArgs
    {
        public BlockGraph BlockGraph { get; }

        public BlockGraphEventArgs(BlockGraph blockGraph)
        {
            BlockGraph = blockGraph;
        }
    }

    private readonly ISystemCore _systemCore;
    private readonly ILogger _logger;
    private readonly IObservable<EventPattern<BlockGraphEventArgs>> _onRoundCompleted;
    private readonly IDisposable _onRoundListener;
    private readonly Caching<BlockGraph> _syncCacheBlockGraph = new();
    private readonly Caching<Block> _syncCacheDelivered = new();
    private readonly Caching<SeenBlockGraph> _syncCacheSeenBlockGraph = new();
    private IDisposable _disposableHandelSeenBlockGraphs;
    private bool _disposed;
    private readonly SemaphoreSlim _slimDecideWinner = new(1, 1);
    private int _roundCompleted = 1;

    /// <summary>
    /// </summary>
    private EventHandler<BlockGraphEventArgs> _onRoundCompletedEventHandler;

    /// <summary>
    /// </summary>
    /// <param name="systemCore"></param>
    /// <param name="logger"></param>
    public Graph(ISystemCore systemCore, ILogger logger) : base(
        new ExecutionDataflowBlockOptions { BoundedCapacity = 100, MaxDegreeOfParallelism = 2, EnsureOrdered = true })
    {
        _systemCore = systemCore;
        _logger = logger.ForContext("SourceContext", nameof(Graph));
        _onRoundCompleted = Observable.FromEventPattern<BlockGraphEventArgs>(ev => _onRoundCompletedEventHandler += ev,
            ev => _onRoundCompletedEventHandler -= ev);
        _onRoundListener = OnRoundListener();
        Init();
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="blockGraph"></param>
    protected override async Task OnReceiveAsync(BlockGraph blockGraph)
    {
        Guard.Argument(blockGraph, nameof(blockGraph)).NotNull();
        if (_systemCore.Sync().Running) return;
        if (blockGraph.Block.Round != NextRound()) return;
        var identifier = blockGraph.ToIdentifier();
        if (await BlockHeightExistsAsync(new BlockHeightExistsRequest(blockGraph.Block.Round)) != VerifyResult.Succeed) return;
        if (!_syncCacheSeenBlockGraph.Contains(identifier))
        {
            _syncCacheSeenBlockGraph.Add(identifier,
                new SeenBlockGraph
                { Hash = blockGraph.Block.BlockHash, Round = blockGraph.Block.Round, Key = identifier });
            await FinalizeAsync(blockGraph);
        }
    }

    /// <summary>
    /// </summary>
    /// <param name="blockGraph"></param>
    public new async Task PostAsync(BlockGraph blockGraph)
    {
        Guard.Argument(blockGraph, nameof(blockGraph)).NotNull();
        await base.PostAsync(blockGraph);
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="transactionIndexRequest"></param>
    /// <returns></returns>
    public async Task<TransactionBlockIndexResponse> GetTransactionBlockIndexAsync(
        TransactionBlockIndexRequest transactionIndexRequest)
    {
        Guard.Argument(transactionIndexRequest, nameof(transactionIndexRequest)).NotNull();
        try
        {
            var transactionBlock = await GetTransactionBlockAsync(new TransactionIdRequest(transactionIndexRequest.TransactionId));
            if (transactionBlock is { })
            {
                return new TransactionBlockIndexResponse(transactionBlock.Block.Height);
            }
        }
        catch (Exception ex)
        {
            _logger.Here().Error("{@Message}", ex.Message);
        }

        return new TransactionBlockIndexResponse(0);
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="transactionIdRequest"></param>
    /// <returns></returns>
    public async Task<BlockResponse> GetTransactionBlockAsync(TransactionIdRequest transactionIdRequest)
    {
        Guard.Argument(transactionIdRequest, nameof(transactionIdRequest)).NotNull();
        try
        {
            var unitOfWork = _systemCore.UnitOfWork();
            var block = await unitOfWork.HashChainRepository.GetAsync(x =>
                new ValueTask<bool>(x.Txs.Any(t => t.TxnId.Xor(transactionIdRequest.TransactionId))));
            if (block is { })
            {
                return new BlockResponse(block);
            }
        }
        catch (Exception ex)
        {
            _logger.Here().Error("{@Message}", ex.Message);
        }

        return new BlockResponse(null);
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="transactionRequest"></param>
    /// <returns></returns>
    public async Task<TransactionResponse> GetTransactionAsync(TransactionRequest transactionRequest)
    {
        Guard.Argument(transactionRequest, nameof(transactionRequest)).NotNull();
        try
        {
            var unitOfWork = _systemCore.UnitOfWork();
            var blocks = await unitOfWork.HashChainRepository.WhereAsync(x =>
                new ValueTask<bool>(x.Txs.Any(t => t.TxnId.Xor(transactionRequest.TransactionId))));
            var block = blocks.FirstOrDefault();
            var transaction = block?.Txs.FirstOrDefault(x => x.TxnId.Xor(transactionRequest.TransactionId));
            if (transaction is { })
            {
                return new TransactionResponse(transaction);
            }
        }
        catch (Exception ex)
        {
            _logger.Here().Error("{@Message}", ex.Message);
        }

        return new TransactionResponse(null);
    }

    /// <summary>
    /// </summary>
    /// <returns></returns>
    public async Task<Block> GetPreviousBlockAsync()
    {
        var hashChainRepository = _systemCore.UnitOfWork().HashChainRepository;
        var prevBlock =
            await hashChainRepository.GetAsync(x =>
                new ValueTask<bool>(x.Height == hashChainRepository.Height));
        return prevBlock;
    }

    /// <summary>
    /// </summary>
    /// <param name="safeguardBlocksRequest"></param>
    /// <returns></returns>
    public async Task<SafeguardBlocksResponse> GetSafeguardBlocksAsync(SafeguardBlocksRequest safeguardBlocksRequest)
    {
        Guard.Argument(safeguardBlocksRequest, nameof(safeguardBlocksRequest)).NotNull();
        try
        {
            var hashChainRepository = _systemCore.UnitOfWork().HashChainRepository;
            var height = hashChainRepository.Height <= (ulong)safeguardBlocksRequest.NumberOfBlocks ? 0 : hashChainRepository.Height - (ulong)safeguardBlocksRequest.NumberOfBlocks;
            var blocks = await hashChainRepository.OrderByRangeAsync(x => x.Height, (int)height,
                safeguardBlocksRequest.NumberOfBlocks);
            if (blocks.Any()) return new SafeguardBlocksResponse(blocks, string.Empty);
        }
        catch (Exception ex)
        {
            _logger.Here().Error("{@Message}", ex.Message);
        }

        return new SafeguardBlocksResponse(new List<Block>(Array.Empty<Block>()), "Sequence contains zero elements");
    }

    /// <summary>
    /// </summary>
    /// <param name="blockRequest"></param>
    /// <returns></returns>
    public async Task<BlockResponse> GetBlockAsync(BlockRequest blockRequest)
    {
        Guard.Argument(blockRequest, nameof(blockRequest)).NotNull();
        try
        {
            var block = await _systemCore.UnitOfWork().HashChainRepository.GetAsync(blockRequest.Hash);
            if (block is { }) return new BlockResponse(block);
        }
        catch (Exception ex)
        {
            _logger.Here().Error("{@Message}", ex.Message);
        }

        return new BlockResponse(null);
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="blockByHeightRequest"></param>
    /// <returns></returns>
    public async Task<BlockResponse> GetBlockByHeightAsync(BlockByHeightRequest blockByHeightRequest)
    {
        Guard.Argument(blockByHeightRequest, nameof(blockByHeightRequest)).NotNull();
        try
        {
            var block = await _systemCore.UnitOfWork().HashChainRepository.GetAsync(x =>
                new ValueTask<bool>(x.Height == blockByHeightRequest.Height));
            if (block is { }) return new BlockResponse(block);
        }
        catch (Exception ex)
        {
            _logger.Here().Error("{@Message}", ex.Message);
        }

        return new BlockResponse(null);
    }

    /// <summary>
    /// </summary>
    /// <param name="blocksRequest"></param>
    public async Task<BlocksResponse> GetBlocksAsync(BlocksRequest blocksRequest)
    {
        Guard.Argument(blocksRequest, nameof(blocksRequest)).NotNull();
        try
        {
            var unitOfWork = _systemCore.UnitOfWork();
            var (skip, take) = blocksRequest;
            var blocks = await unitOfWork.HashChainRepository.OrderByRangeAsync(x => x.Height, skip, take);
            if (blocks.Any()) return new BlocksResponse(blocks);
        }
        catch (Exception ex)
        {
            _logger.Here().Error("{@Message}", ex.Message);
        }

        return new BlocksResponse(null);
    }

    /// <summary>
    /// </summary>
    /// <param name="saveBlockRequest"></param>
    public async Task<SaveBlockResponse> SaveBlockAsync(SaveBlockRequest saveBlockRequest)
    {
        Guard.Argument(saveBlockRequest, nameof(saveBlockRequest)).NotNull();
        try
        {
            if (await _systemCore.Validator().VerifyBlockAsync(saveBlockRequest.Block) != VerifyResult.Succeed)
            {
                return new SaveBlockResponse(false);
            }
            var unitOfWork = _systemCore.UnitOfWork();
            if (await unitOfWork.HashChainRepository.PutAsync(saveBlockRequest.Block.Hash, saveBlockRequest.Block))
                return new SaveBlockResponse(true);
        }
        catch (Exception ex)
        {
            _logger.Here().Error("{@Message}", ex.Message);
        }

        return new SaveBlockResponse(false);
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="blockHeightExistsRequest"></param>
    /// <returns></returns>
    public async Task<VerifyResult> BlockHeightExistsAsync(BlockHeightExistsRequest blockHeightExistsRequest)
    {
        Guard.Argument(blockHeightExistsRequest, nameof(blockHeightExistsRequest)).NotNull();
        var unitOfWork = _systemCore.UnitOfWork();
        var seen = await unitOfWork.HashChainRepository.GetAsync(x => new ValueTask<bool>(x.Height == blockHeightExistsRequest.Height));
        return seen is not null ? VerifyResult.AlreadyExists : VerifyResult.Succeed;
    }

    /// <summary>
    /// </summary>
    /// <param name="blockExistsRequest"></param>
    /// <returns></returns>
    public async Task<VerifyResult> BlockExistsAsync(BlockExistsRequest blockExistsRequest)
    {
        Guard.Argument(blockExistsRequest, nameof(blockExistsRequest)).NotNull();
        Guard.Argument(blockExistsRequest.Hash, nameof(blockExistsRequest.Hash)).NotNull().NotEmpty().MaxCount(64);
        var unitOfWork = _systemCore.UnitOfWork();
        var seen = await unitOfWork.HashChainRepository.GetAsync(x => new ValueTask<bool>(x.Hash.Xor(blockExistsRequest.Hash)));
        return seen is not null ? VerifyResult.AlreadyExists : VerifyResult.Succeed;
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="hashTransactionsRequest"></param>
    /// <returns></returns>
    public byte[] HashTransactions(HashTransactionsRequest hashTransactionsRequest)
    {
        Guard.Argument(hashTransactionsRequest, nameof(hashTransactionsRequest)).NotNull();
        if (hashTransactionsRequest.Transactions.Length == 0) return null;
        using BufferStream ts = new();
        foreach (var transaction in hashTransactionsRequest.Transactions) ts.Append(transaction.ToStream());
        return Hasher.Hash(ts.ToArray()).HexToByte();
    }

    /// <summary>
    /// 
    /// </summary>
    /// <returns></returns>
    public async Task<bool> BlockCountSynchronizedAsync()
    {
        var maxBlockCount = await _systemCore.PeerDiscovery().NetworkBlockCountAsync();
        return _systemCore.UnitOfWork().HashChainRepository.Count >= maxBlockCount;
    }

    /// <summary>
    /// </summary>
    private void Init()
    {
        HandelSeenBlockGraphs();
    }

    /// <summary>
    /// </summary>
    /// <param name="e"></param>
    private void OnRoundReady(BlockGraphEventArgs e)
    {
        if (e.BlockGraph.Block.Round != NextRound()) return;
        _onRoundCompletedEventHandler?.Invoke(this, e);
    }

    /// <summary>
    /// </summary>
    private void HandelSeenBlockGraphs()
    {
        _disposableHandelSeenBlockGraphs = Observable.Interval(TimeSpan.FromMinutes(15)).Subscribe(_ =>
        {
            if (_systemCore.ApplicationLifetime.ApplicationStopping.IsCancellationRequested) return;
            try
            {
                var removeSeenBlockGraphBeforeTimestamp = Helper.Util.GetUtcNow().AddMinutes(-15).ToUnixTimestamp();
                var removingBlockGraphs = AsyncHelper.RunSync(async delegate
                {
                    return await _syncCacheSeenBlockGraph.WhereAsync(x =>
                        new ValueTask<bool>(x.Value.Timestamp < removeSeenBlockGraphBeforeTimestamp));
                });
                foreach (var (key, _) in removingBlockGraphs.OrderBy(x => x.Value.Round))
                {
                    _syncCacheSeenBlockGraph.Remove(key);
                    _syncCacheBlockGraph.Remove(key);
                }
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
    /// </summary>
    /// <returns></returns>
    private IDisposable OnRoundListener()
    {
        var onRoundCompletedSubscription = _onRoundCompleted
            .Where(data => data.EventArgs.BlockGraph.Block.Round == NextRound())
            .Throttle(TimeSpan.FromSeconds(LedgerConstant.OnRoundThrottleFromSeconds), NewThreadScheduler.Default)
            .SubscribeOn(Scheduler.Default)
            .Subscribe(_ =>
            {
                try
                {
                    var blockGraphs = _syncCacheBlockGraph.GetItems().Where(x => x.Block.Round == NextRound()).ToList();
                    var nodeCount = blockGraphs.Select(n => n.Block.Node).Distinct().Count();
                    var f = (nodeCount - 1) / 3;
                    var quorum2F1 = 2 * f + 1;
                    if (nodeCount < quorum2F1) return;
                    var lastInterpreted = GetRound();
                    var config = new Consensus.Models.Config(lastInterpreted, Array.Empty<ulong>(),
                        _systemCore.NodeId(), (ulong)nodeCount);
                    var blockmania = new Blockmania(config, _logger) { NodeCount = nodeCount };
                    blockmania.TrackingDelivered.Subscribe(x =>
                    {
                        OnDeliveredReadyAsync(x.EventArgs.Interpreted).SafeFireAndForget();
                    });
                    foreach (var next in blockGraphs)
                    {
                        AsyncHelper.RunSync(async () =>
                        {
                            await blockmania.AddAsync(next,
                                _systemCore.ApplicationLifetime.ApplicationStopping);
                        });
                    }
                }
                catch (Exception ex)
                {
                    _logger.Here().Error(ex, "Process add blockmania error");
                }
            }, exception => { _logger.Here().Error(exception, "Subscribe try add blockmania listener error"); });
        return onRoundCompletedSubscription;
    }

    /// <summary>
    /// </summary>
    /// <param name="blockGraph"></param>
    /// <returns></returns>
    private bool Save(BlockGraph blockGraph)
    {
        Guard.Argument(blockGraph, nameof(blockGraph)).NotNull();
        try
        {
            if (_systemCore.Validator().VerifyBlockGraphNodeRound(ref blockGraph) != VerifyResult.Succeed)
            {
                _logger.Error("Unable to verify block for {@Node} and round {@Round}", blockGraph.Block.Node,
                    blockGraph.Block.Round);
                _syncCacheBlockGraph.Remove(blockGraph.ToIdentifier());
                return false;
            }

            _syncCacheBlockGraph.Add(blockGraph.ToIdentifier(), blockGraph);
        }
        catch (Exception)
        {
            _logger.Here().Error("Unable to save block for {@Node} and round {@Round}", blockGraph.Block.Node,
                blockGraph.Block.Round);
            return false;
        }

        return true;
    }

    /// <summary>
    /// </summary>
    /// <returns></returns>
    private async Task FinalizeAsync(BlockGraph blockGraph)
    {
        Guard.Argument(blockGraph, nameof(blockGraph)).NotNull();
        try
        {
            if (!Save(blockGraph)) return;
            if (_systemCore.NodeId() == blockGraph.Block.Node)
            {
                await BroadcastAsync(blockGraph);
                return;
            }

            var copy = Copy(blockGraph);
            await BroadcastAsync(copy);
            OnRoundReady(new BlockGraphEventArgs(blockGraph));
        }
        catch (Exception)
        {
            _logger.Here().Error("Unable to add block for {@Node} and round {@Round}", blockGraph.Block.Node,
                blockGraph.Block.Round);
        }
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="blockGraph"></param>
    /// <returns></returns>
    private BlockGraph Copy(BlockGraph blockGraph)
    {
        Guard.Argument(blockGraph, nameof(blockGraph)).NotNull();
        try
        {
            var localNodeId = _systemCore.NodeId();
            var copy = new BlockGraph
            {
                Block = new Consensus.Models.Block
                {
                    BlockHash = blockGraph.Block.BlockHash,
                    Data = blockGraph.Block.Data,
                    DataHash = blockGraph.Block.DataHash,
                    Hash = blockGraph.Block.Hash,
                    Node = localNodeId,
                    Round = blockGraph.Block.Round
                },
                Prev = new Consensus.Models.Block
                {
                    BlockHash = blockGraph.Prev.BlockHash,
                    Data = Array.Empty<byte>(),
                    DataHash = string.Empty,
                    Hash = blockGraph.Prev.Hash,
                    Node = localNodeId,
                    Round = blockGraph.Prev.Round
                }
            };
            return copy;
        }
        catch (Exception ex)
        {
            _logger.Here().Error("{@Message}", ex.Message);
        }

        return null;
    }

    /// <summary>
    /// </summary>
    /// <param name="deliver"></param>
    /// <returns></returns>
    private async Task OnDeliveredReadyAsync(Consensus.Models.Interpreted deliver)
    {
        Guard.Argument(deliver, nameof(deliver)).NotNull();
        _logger.Information("Delivered: {@Count} Consumed: {@Consumed} Round: {@Round}", deliver.Blocks.Count,
            deliver.Consumed, deliver.Round);
        var blocks = deliver.Blocks.Where(x => x.Data is { });
        foreach (var deliveredBlock in blocks)
            try
            {
                if (deliveredBlock.Round != NextRound()) continue;
                await using var stream =
                    Helper.Util.Manager.GetStream(deliveredBlock.Data.AsSpan()) as RecyclableMemoryStream;
                var block = await MessagePackSerializer.DeserializeAsync<Block>(stream);
                if (await _systemCore.Validator().VerifyBlockHashAsync(block) != VerifyResult.Succeed)
                {
                    var nodeId = block.BlockPos.PublicKey.ToHashIdentifier();
                    var ipAddress = _systemCore.PeerDiscovery().GetGossipMemberStore()
                        .FirstOrDefault(x => x.NodeId == nodeId).IpAddress;
                    _systemCore.PeerDiscovery().SetPeerCooldown(new PeerCooldown
                    {
                        IpAddress = ipAddress ?? Array.Empty<byte>(),
                        PublicKey = block.BlockPos.PublicKey,
                        NodeId = nodeId,
                        PeerState = PeerState.OrphanBlock
                    });
                    await _systemCore.UnitOfWork().OrphanBlockRepository.PutAsync(block.Hash, block);
                    _logger.Warning(
                        "Orphan block [UNABLE TO VERIFY] Hash: {@Hash} Round: {@Round} Node: {@Node} Sol: {@Sol}",
                        block.Hash.ByteToHex(), deliveredBlock.Round, deliveredBlock.Node, block.BlockPos.Solution);
                    continue;
                }

                _syncCacheDelivered.AddOrUpdate(block.Hash, block);
            }
            catch (Exception ex)
            {
                _logger.Here().Error("{@Message}", ex.Message);
            }

        await DecideWinnerAsync();
    }

    /// <summary>
    /// </summary>
    private async Task DecideWinnerAsync()
    {
        await _slimDecideWinner.WaitAsync();
        Block[] deliveredBlocks = null;
        try
        {
            deliveredBlocks = _syncCacheDelivered.Where(x => x.Value.Height == NextRound())
                .Select(n => n.Value)
                .ToArray();
            if (deliveredBlocks.Any() != true) return;
            Block block = null;
            foreach (var x in deliveredBlocks)
            {
                if (BinomialCdfWalk(
                        Hasher.Hash(x.BlockPos.VrfSig).HexToByte().ToBigInteger() % LedgerConstant.MagicNumber,
                        deliveredBlocks.Length) != deliveredBlocks.Select(n =>
                        BinomialCdfWalk(
                            Hasher.Hash(n.BlockPos.VrfSig).HexToByte().ToBigInteger() % LedgerConstant.MagicNumber,
                            deliveredBlocks.Length)).Min()) continue;
                block = x;
                break;
            }

            if (block.Height != NextRound()) return;
            if (await BlockHeightExistsAsync(new BlockHeightExistsRequest(block.Height)) == VerifyResult.AlreadyExists)
            {
                _logger.Error("Block winner already exists");
                return;
            }

            var saveBlockResponse = await SaveBlockAsync(new SaveBlockRequest(block));
            if (saveBlockResponse.Ok)
            {
                if (block.BlockPos.PublicKey.ToHashIdentifier() == _systemCore.PeerDiscovery().GetLocalNode().NodeId)
                    AnsiConsole.Write(new FigletText("# Block Winner #").Centered().Color(Color.Magenta1));
                else
                    _logger.Information("We have a winner {@Hash} Solution {@Sol} Node {@Node}", block.Hash.ByteToHex(),
                        block.BlockPos.Solution, block.BlockPos.PublicKey.ToHashIdentifier());
            }
            else
            {
                var seenBlockGraph = _syncCacheSeenBlockGraph.GetItems().FirstOrDefault(x => x.Hash.Xor(block.Hash));
                if (seenBlockGraph != null) _syncCacheBlockGraph.Remove(seenBlockGraph.Key);
                _logger.Error("Unable to save the block winner");
            }
        }
        catch (Exception ex)
        {
            _logger.Here().Error(ex, "Decide winner failed");
        }
        finally
        {
            if (deliveredBlocks is { })
                foreach (var block in deliveredBlocks)
                {
                    _syncCacheDelivered.Remove(block.Hash);
                    if (block.BlockPos.PublicKey.ToHashIdentifier() == _systemCore.NodeId())
                        _systemCore.WalletSession().Notify(block.Txs.ToArray());
                }
            
            _slimDecideWinner.Release();
        }
    }

    /// <summary>
    /// 
    /// </summary>
    /// <returns></returns>
    private ulong GetRound()
    {
        return _systemCore.UnitOfWork().HashChainRepository.Height;
    }

    /// <summary>
    /// 
    /// </summary>
    /// <returns></returns>
    private ulong NextRound()
    {
        return _systemCore.UnitOfWork().HashChainRepository.Count;
    }

    /// <summary>
    /// </summary>
    /// <param name="blockGraph"></param>
    /// <returns></returns>
    private async Task BroadcastAsync(BlockGraph blockGraph)
    {
        Guard.Argument(blockGraph, nameof(blockGraph)).NotNull();
        try
        {
            if (blockGraph.Block.Round == NextRound())
                await _systemCore.Broadcast().PostAsync((TopicType.AddBlockGraph,
                    MessagePackSerializer.Serialize(blockGraph)));
        }
        catch (Exception ex)
        {
            _logger.Here().Error(ex, "Broadcast error");
        }
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="n"></param>
    /// <param name="k"></param>
    /// <returns></returns>
    private static BigInteger BinomialCdfWalk(BigInteger n, int k)
    {
        BigInteger result = 0;
        for (var i = 0; i <= k; i++)
        {
            result += BinomialCoefficient(n, i);
        }
        return result;
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="n"></param>
    /// <param name="k"></param>
    /// <returns></returns>
    private static BigInteger BinomialCoefficient(BigInteger n, int k)
    {
        BigInteger result = 1;
        for (var i = 0; i < k; i++)
        {
            result = result * (n - i) / (i + 1);
        }
        return result;
    }
    
    /// <summary>
    /// 
    /// </summary>
    /// <param name="disposing"></param>
    private void Dispose(bool disposing)
    {
        if (_disposed)
        {
            return;
        }

        if (disposing)
        {
            _onRoundListener?.Dispose();
            _disposableHandelSeenBlockGraphs?.Dispose();
        }

        _disposed = true;
    }

    /// <summary>
    /// 
    /// </summary>
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }
}