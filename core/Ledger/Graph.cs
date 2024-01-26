// Tangram by Matthew Hellyer is licensed under CC BY-NC-ND 4.0.
// To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
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
using TangramXtgm.Persistence;
using Block = TangramXtgm.Models.Block;

namespace TangramXtgm.Ledger;

/// <summary>
/// Interface for interacting with a graph of blockchain blocks.
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
    BlockGraph SignBlockGraph(BlockGraph blockGraph);

}

/// <summary>
/// Represents a graph of seen blocks.
/// </summary>
internal record SeenBlockGraph
{
    /// <summary
    public long Timestamp { get; } = Helper.Util.GetAdjustedTimeAsUnixTimestamp();
    public ulong Round { get; init; }
    public byte[] Hash { get; init; }
    public byte[] Key { get; init; }
}

/// <summary>
/// Represents a graph of blocks.
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
    /// <summary>
    /// Event handler for the completion of a round in a block graph.
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
    /// This method is called when a BlockGraph is received.
    /// </summary>
    /// <param name="blockGraph">The BlockGraph that was received.</param>
    /// <returns>A Task representing the asynchronous operation.</returns>
    protected override async Task OnReceiveAsync(BlockGraph blockGraph)
    {
        Guard.Argument(blockGraph, nameof(blockGraph)).NotNull();
        if (_systemCore.Sync().SyncRunning) return;
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
    /// Posts the specified block graph asynchronously.
    /// </summary>
    /// <param name="blockGraph">The block graph to post.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    public new Task PostAsync(BlockGraph blockGraph)
    {
        Guard.Argument(blockGraph, nameof(blockGraph)).NotNull();
        return base.PostAsync(blockGraph);
    }

    /// <summary>
    /// Retrieves the block index of a transaction asynchronously.
    /// </summary>
    /// <param name="transactionIndexRequest">The request object containing the transaction ID.</param>
    /// <returns>A task that represents the asynchronous operation. The task result contains the response object that contains the block index of the transaction.</returns>
    public async Task<TransactionBlockIndexResponse> GetTransactionBlockIndexAsync(
        TransactionBlockIndexRequest transactionIndexRequest)
    {
        Guard.Argument(transactionIndexRequest, nameof(transactionIndexRequest)).NotNull();
        try
        {
            var transactionBlock = await GetTransactionBlockAsync(new TransactionIdRequest(transactionIndexRequest.TransactionId));
            if (transactionBlock is not null)
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
    /// Retrieves the block containing the specified transaction asynchronously.
    /// </summary>
    /// <param name="transactionIdRequest">The request object containing the transaction ID.</param>
    /// <returns>A task that represents the asynchronous operation. The task result contains a BlockResponse object.</returns>
    public async Task<BlockResponse> GetTransactionBlockAsync(TransactionIdRequest transactionIdRequest)
    {
        Guard.Argument(transactionIdRequest, nameof(transactionIdRequest)).NotNull();
        try
        {
            var unitOfWork = _systemCore.UnitOfWork();
            var block = await unitOfWork.HashChainRepository.GetAsync(x =>
                new ValueTask<bool>(x.Txs.Any(t => t.TxnId.Xor(transactionIdRequest.TransactionId))));
            if (block is not null)
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
    /// Retrieves a transaction asynchronously.
    /// </summary>
    /// <param name="transactionRequest">The transaction request object.</param>
    /// <returns>The transaction response object.</returns>
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
            if (transaction is not null)
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
    /// Gets the previous block asynchronously.
    /// </summary>
    /// <returns>
    /// The previous <see cref="Block"/>.
    /// </returns>
    public async Task<Block> GetPreviousBlockAsync()
    {
        var prevBlock =
            await _systemCore.UnitOfWork().HashChainRepository.GetAsync(x =>
                new ValueTask<bool>(x.Height == _systemCore.UnitOfWork().HashChainRepository.Height));
        return prevBlock;
    }

    /// <summary>
    /// Retrieves a specified number of safeguard blocks from the hash chain repository.
    /// </summary>
    /// <param name="safeguardBlocksRequest">The request object containing the number of blocks to retrieve.</param>
    /// <returns>A task representing the asynchronous operation. The task result contains a <see cref="SafeguardBlocksResponse"/> object.</returns>
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
    /// Retrieves a block asynchronously using the provided block request.
    /// </summary>
    /// <param name="blockRequest">The block request containing the necessary information to retrieve the block.</param>
    /// <returns>Returns a task that represents the asynchronous operation. The task result contains the block response.</returns>
    public async Task<BlockResponse> GetBlockAsync(BlockRequest blockRequest)
    {
        Guard.Argument(blockRequest, nameof(blockRequest)).NotNull();
        try
        {
            var block = await _systemCore.UnitOfWork().HashChainRepository.GetAsync(blockRequest.Hash);
            if (block is not null) return new BlockResponse(block);
        }
        catch (Exception ex)
        {
            _logger.Here().Error("{@Message}", ex.Message);
        }

        return new BlockResponse(null);
    }

    /// <summary>
    /// Retrieves a block with the specified height asynchronously.
    /// </summary>
    /// <param name="blockByHeightRequest">The request object specifying the block height.</param>
    /// <returns>A Task that represents the asynchronous operation. The task result contains the response object representing the retrieved block.</returns>
    public async Task<BlockResponse> GetBlockByHeightAsync(BlockByHeightRequest blockByHeightRequest)
    {
        Guard.Argument(blockByHeightRequest, nameof(blockByHeightRequest)).NotNull();
        try
        {
            var block = await _systemCore.UnitOfWork().HashChainRepository.GetAsync(x =>
                new ValueTask<bool>(x.Height == blockByHeightRequest.Height));
            if (block is not null) return new BlockResponse(block);
        }
        catch (Exception ex)
        {
            _logger.Here().Error("{@Message}", ex.Message);
        }

        return new BlockResponse(null);
    }

    /// <summary>
    /// Retrieves the requested blocks asynchronously.
    /// </summary>
    /// <param name="blocksRequest">The request containing the necessary parameters for retrieving the blocks.</param>
    /// <returns>The response containing the retrieved blocks. If no blocks are found, a response with a null value is returned.</returns>
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
    /// Saves a block asynchronously.
    /// </summary>
    /// <param name="saveBlockRequest">The request object containing the block to be saved.</param>
    /// <returns>A response object indicating whether the block was saved successfully.</returns>
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
    /// Checks if a block height already exists.
    /// </summary>
    /// <param name="blockHeightExistsRequest">The request object containing the block height to check.</param>
    /// <returns>A VerifyResult indicating the result of the verification.</returns>
    public async Task<VerifyResult> BlockHeightExistsAsync(BlockHeightExistsRequest blockHeightExistsRequest)
    {
        Guard.Argument(blockHeightExistsRequest, nameof(blockHeightExistsRequest)).NotNull();
        var unitOfWork = _systemCore.UnitOfWork();
        var seen = await unitOfWork.HashChainRepository.GetAsync(x => new ValueTask<bool>(x.Height == blockHeightExistsRequest.Height));
        return seen is not null ? VerifyResult.AlreadyExists : VerifyResult.Succeed;
    }

    /// <summary>
    /// Checks if a block exists in the hash chain.
    /// </summary>
    /// <param name="blockExistsRequest">The request containing the block hash to check.</param>
    /// <returns>A VerifyResult indicating the status of the block existence.</returns>
    public async Task<VerifyResult> BlockExistsAsync(BlockExistsRequest blockExistsRequest)
    {
        Guard.Argument(blockExistsRequest, nameof(blockExistsRequest)).NotNull();
        Guard.Argument(blockExistsRequest.Hash, nameof(blockExistsRequest.Hash)).NotNull().NotEmpty().MaxCount(64);
        var unitOfWork = _systemCore.UnitOfWork();
        var seen = await unitOfWork.HashChainRepository.GetAsync(x => new ValueTask<bool>(x.Hash.Xor(blockExistsRequest.Hash)));
        return seen is not null ? VerifyResult.AlreadyExists : VerifyResult.Succeed;
    }

    /// <summary>
    /// Hashes the transactions provided in the <paramref name="hashTransactionsRequest"/> and returns the result as a byte array.
    /// </summary>
    /// <param name="hashTransactionsRequest">The request object containing the transactions to be hashed.</param>
    /// <returns>The hashed transactions as a byte array.</returns>
    public byte[] HashTransactions(HashTransactionsRequest hashTransactionsRequest)
    {
        Guard.Argument(hashTransactionsRequest, nameof(hashTransactionsRequest)).NotNull();
        if (hashTransactionsRequest.Transactions.Length == 0) return null;
        using BufferStream ts = new();
        foreach (var transaction in hashTransactionsRequest.Transactions) ts.Append(transaction.ToStream());
        return Hasher.Hash(ts.ToArray()).HexToByte();
    }

    /// <summary>
    /// Checks if the number of blocks in the HashChainRepository is synchronized with the network block count.
    /// </summary>
    /// <remarks>
    /// This method asynchronously retrieves the network block count from the PeerDiscovery class and compares it with the number of blocks stored in the HashChainRepository.
    /// </remarks>
    /// <returns>
    /// A boolean value indicating if the number of blocks stored in the HashChainRepository is equal to or greater than the network block count.
    /// </returns>
    public async Task<bool> BlockCountSynchronizedAsync()
    {
        var maxBlockCount = await _systemCore.PeerDiscovery().NetworkBlockCountAsync();
        return _systemCore.UnitOfWork().HashChainRepository.Count >= maxBlockCount;
    }

    /// <summary>
    /// Initializes the object and handles seen block graphs.
    /// </summary>
    private void Init()
    {
        HandelSeenBlockGraphs();
    }

    /// <summary>
    /// Called when a round is ready.
    /// </summary>
    /// <param name="e">The event arguments containing the block graph data.</param>
    private void OnRoundReady(BlockGraphEventArgs e)
    {
        if (e.BlockGraph.Block.Round != NextRound()) return;
        _onRoundCompletedEventHandler?.Invoke(this, e);
    }

    /// <summary>
    /// Handles the removal of seen block graphs.
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
    /// Replays the blocks asynchronously.
    /// </summary>
    /// <returns>A task representing the asynchronous operation.</returns>
    private async Task CheckReplayAsync()
    {
        var blockGraphs = _syncCacheBlockGraph.GetItems().Where(x => x.Block.Round == NextRound()).ToArray();
        if (!blockGraphs.Any()) return;

        if (await ValidateAndReplayBlocksAsync())
        {
            var blocks = new ConcurrentBag<Block>();
            var lastInterpreted = GetRound();
            var blockByHeight = await GetBlockByHeightAsync(new BlockByHeightRequest(lastInterpreted));
            try
            {
                blocks.Add(blockByHeight.Block);
                var peers = blockGraphs.Select(blockGraph => _systemCore.PeerDiscovery().GetGossipMemberStore()
                    .FirstOrDefault(x => x.NodeId == blockGraph.Block.Node)).ToArray();
                var random = new Random();
                var n = peers.Length;
                while (n > 1)
                {
                    n--;
                    var k = random.Next(n + 1);
                    (peers[k], peers[n]) = (peers[n], peers[k]);
                }

                peers = peers.Take(QuorumF(peers.Length)).ToArray();
                await Parallel.ForEachAsync(peers, async (peer, token) =>
                {
                    try
                    {
                        var blockResponse = await _systemCore.GossipMemberStore().SendAsync<BlockResponse>(
                            new IPEndPoint(IPAddress.Parse(peer.IpAddress.FromBytes()), peer.TcpPort.ToInt32()),
                            peer.PublicKey,
                            MessagePackSerializer.Serialize(new Parameter[]
                            {
                                new() { Value = lastInterpreted.ToBytes(), ProtocolCommand = ProtocolCommand.GetBlock },
                                new() { Value = lastInterpreted.ToBytes(), ProtocolCommand = ProtocolCommand.GetBlock }
                            }, cancellationToken: token));
                        if (blockResponse?.Block is null) return;
                        if (await _systemCore.Validator().VerifyBlockHashAsync(blockResponse.Block) ==
                            VerifyResult.Succeed)
                            blocks.Add(blockResponse.Block);
                    }
                    catch (Exception e)
                    {
                        _logger.Here().Error("{@Message}", e.Message);
                    }
                });
                if (!blocks.Any()) return;
                var block = BlockSelector(blocks.ToArray());
                if (!block.Hash.Xor(blockByHeight.Block.Hash))
                {
                    _systemCore.UnitOfWork().HashChainRepository
                        .Delete(blockByHeight.Block.Hash, blockByHeight.Block.BlockHeader.PrevBlockHash);
                    await SaveBlockAsync(new SaveBlockRequest(block));
                }
            }
            catch (Exception e)
            {
                _logger.Here().Error("{@Message}", e.Message);
            }
            finally
            {
                await _systemCore.Sync().SetSyncRunningAsync(false);
            }
        }
    }

    /// <summary>
    /// Validates the blocks in the sync cache that have the same height as the next round.
    /// </summary>
    /// <returns>A task representing the asynchronous operation. The task result is a boolean value indicating whether any blocks were validated.</returns>
    private async Task<bool> ValidateAndReplayBlocksAsync()
    {
        foreach (var block in _syncCacheDelivered.GetItems().Where(x => x.Height == NextRound()))
        {
            if (await _systemCore.Validator().VerifyBlockHashAsync(block) == VerifyResult.Succeed)
                continue;

            await _systemCore.Sync().SetSyncRunningAsync(true);
            return true;
        }

        return false;
    }

    /// <summary>
    /// Subscribes to the OnRoundCompleted event and performs specific actions when a round is completed.
    /// </summary>
    /// <returns>An IDisposable object that allows for unsubscribing from the event.</returns>
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
                    var noDupKeys = new List<byte[]>();
                    foreach (var blockGraphSignature in blockGraphs.SelectMany(blockGraph => blockGraph.Signatures))
                    {
                        if (noDupKeys.FirstOrDefault(x => x.Xor(blockGraphSignature.Signature)) is not null)
                            throw new Exception("Duplicate signature found");
                        noDupKeys.Add(blockGraphSignature.Signature);
                    }

                    var nodeCount = _systemCore.PeerDiscovery().Count();
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
    /// Saves the given BlockGraph object.
    /// </summary>
    /// <param name="blockGraph">The BlockGraph object to be saved.</param>
    /// <returns>Returns true if the BlockGraph object was saved successfully; otherwise, false.</returns>
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
    /// Asynchronously finalizes a block graph after processing.
    /// </summary>
    /// <param name="blockGraph">The block graph to finalize.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
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
    /// Copies the given BlockGraph object.
    /// </summary>
    /// <param name="blockGraph">The BlockGraph object to be copied.</param>
    /// <returns>A new BlockGraph object that is a copy of the input BlockGraph object.</returns>
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
            return SignBlockGraph(copy); ;
        }
        catch (Exception ex)
        {
            _logger.Here().Error("{@Message}", ex.Message);
        }

        return null;
    }

    /// <summary>
    /// Signs a block graph with a Schnorr signature using the system's private key.
    /// </summary>
    /// <param name="blockGraph">The block graph to sign.</param>
    /// <returns>The signed block graph.</returns>
    public BlockGraph SignBlockGraph(BlockGraph blockGraph)
    {
        Guard.Argument(blockGraph, nameof(blockGraph)).NotNull();
        try
        {
            var message = Helper.Util.Combine(blockGraph.Serialize(), blockGraph.Serialize());
            var blockGraphSignature = _systemCore.Crypto().SignSchnorr(_systemCore.KeyPair.PrivateKey.FromSecureString().HexToByte(), message);
            blockGraph.Signatures.Add(new BlockGraphSignature
            {
                PublicKey = _systemCore.KeyPair.PublicKey,
                Signature = blockGraphSignature,
                Message = message
            });
            return blockGraph;
        }
        catch (Exception ex)
        {
            _logger.Here().Error("{@Message}", ex.Message);
        }

        return null;
    }

    /// <summary>
    /// Handles the delivery of a ready consensus message asynchronously.
    /// </summary>
    /// <param name="deliver">The ready consensus message to be delivered.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    private async Task OnDeliveredReadyAsync(Consensus.Models.Interpreted deliver)
    {
        Guard.Argument(deliver, nameof(deliver)).NotNull();
        _logger.Information("Delivered: {@Count} Consumed: {@Consumed} Round: {@Round}", deliver.Blocks.Count,
            deliver.Consumed, deliver.Round);
        var blocks = deliver.Blocks.Where(x => x.Data is not null);
        foreach (var deliveredBlock in blocks)
            try
            {
                if (deliveredBlock.Round != NextRound()) continue;
                await using var stream =
                    Helper.Util.Manager.GetStream(deliveredBlock.Data.AsSpan()) as RecyclableMemoryStream;
                var block = await MessagePackSerializer.DeserializeAsync<Block>(stream);
                _syncCacheDelivered.AddOrUpdate(block.Hash, block);
            }
            catch (Exception ex)
            {
                _logger.Here().Error("{@Message}", ex.Message);
            }

        await DecideWinnerAsync();
    }

    /// <summary>
    /// Method to decide the winner of a block.
    /// </summary>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation.</returns>
    private async Task DecideWinnerAsync()
    {
        await _slimDecideWinner.WaitAsync();
        Block[] deliveredBlocks = null;
        try
        {
            await CheckReplayAsync();
            deliveredBlocks = _syncCacheDelivered.Where(x => x.Value.Height == NextRound()).Select(n => n.Value)
                .ToArray();
            if (deliveredBlocks.Any() != true) return;
            var block = BlockSelector(deliveredBlocks);
            if (block != null && block.Height != NextRound()) return;
            if (await BlockHeightExistsAsync(new BlockHeightExistsRequest(block.Height)) == VerifyResult.AlreadyExists)
            {
                _logger.Error("Block winner already exists");
                return;
            }

            var saveBlockResponse = await SaveBlockAsync(new SaveBlockRequest(block));
            if (saveBlockResponse.Ok)
            {
                await _systemCore.Broadcast().PostAsync((TopicType.OnNewBlock,
                    MessagePackSerializer.Serialize(block)));

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
            if (deliveredBlocks is not null)
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
    /// Selects a block from the given array of delivered blocks based on the minimum value of the Cumulative Distribution Function (CDF) walk.
    /// </summary>
    /// <param name="deliveredBlocks">The array of delivered blocks.</param>
    /// <returns>The selected block.</returns>
    private static Block BlockSelector(Block[] deliveredBlocks)
    {
        Guard.Argument(deliveredBlocks, nameof(deliveredBlocks)).NotNull().NotEmpty();
        Block block = null;

        var minCdfWalk = deliveredBlocks.Select(n =>
            BinomialCdfWalk(
                Hasher.Hash(n.BlockPos.VrfSig).HexToByte().ToBigInteger() % LedgerConstant.MagicNumber,
                deliveredBlocks.Length)).Min();

        foreach (var x in deliveredBlocks)
        {
            if (BinomialCdfWalk(
                    Hasher.Hash(x.BlockPos.VrfSig).HexToByte().ToBigInteger() % LedgerConstant.MagicNumber,
                    deliveredBlocks.Length) != minCdfWalk) continue;
            block = x;
            break;
        }

        return block;
    }

    /// <summary>
    /// Gets the current round of the hash chain.
    /// </summary>
    /// <returns>The current round as an unsigned long.</returns>
    private ulong GetRound()
    {
        return _systemCore.UnitOfWork().HashChainRepository.Height;
    }

    /// <summary>
    /// Retrieves the total count of hash chains in the HashChainRepository and returns it as an unsigned long.
    /// </summary>
    /// <returns>The total count of hash chains</returns>
    private ulong NextRound()
    {
        return _systemCore.UnitOfWork().HashChainRepository.Count;
    }

    /// <summary>
    /// Broadcasts a BlockGraph asynchronously.
    /// </summary>
    /// <param name="blockGraph">The BlockGraph to be broadcasted.</param>
    /// <returns>A Task representing the asynchronous broadcast operation.</returns>
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
    /// Calculates the cumulative probability of a binomial distribution by performing a walk through the coefficients.
    /// </summary>
    /// <param name="n">The total number of trials in the binomial distribution.</param>
    /// <param name="k">The number of successful trials in the binomial distribution.</param>
    /// <returns>The cumulative probability of the binomial distribution represented by the given parameters.</returns>
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
    /// Calculates the binomial coefficient of two given numbers.
    /// </summary>
    /// <param name="n">The total number of items.</param>
    /// <param name="k">The number of items to be selected.</param>
    /// <returns>The binomial coefficient calculated as n! / (k! * (n - k)!).</returns>
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
    /// Calculates the maximum number of failures that a distributed system can tolerate for a given number of nodes.
    /// </summary>
    /// <param name="nodeCount">The total number of nodes in the distributed system.</param>
    /// <returns>The maximum number of failures that the distributed system can tolerate.</returns>
    private static int QuorumF(int nodeCount)
    {
        return (nodeCount - 1) / 3;
    }

    /// <summary>
    /// Disposes the resources used by the object.
    /// </summary>
    /// <param name="disposing">A bool value indicating whether the method is being called from Dispose method or from finalize method.</param>
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
    /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
    /// </summary>
    /// <remarks>
    /// This method is called when the object is no longer needed and is ready to be disposed.
    /// </remarks>
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }
}