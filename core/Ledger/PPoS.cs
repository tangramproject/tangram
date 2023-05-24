// Tangram by Matthew Hellyer is licensed under CC BY-NC-ND 4.0.
// To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Globalization;
using System.Linq;
using System.Reactive.Concurrency;
using System.Reactive.Linq;
using System.Threading;
using System.Threading.Tasks;
using Blake3;
using TangramXtgm.Extensions;
using Dawn;
using libsignal.ecc;
using NBitcoin;
using Serilog;
using TangramXtgm.Consensus.Models;
using TangramXtgm.Cryptography;
using TangramXtgm.Models;
using TangramXtgm.Models.Messages;
using TangramXtgm.Persistence;
using BigInteger = NBitcoin.BouncyCastle.Math.BigInteger;
using Numerics = System.Numerics;
using Block = TangramXtgm.Models.Block;
using BlockHeader = TangramXtgm.Models.BlockHeader;
using Transaction = TangramXtgm.Models.Transaction;
using Util = TangramXtgm.Helper.Util;

namespace TangramXtgm.Ledger;

/// <summary>
/// </summary>
public interface IPPoS
{
    public bool Running { get; }
    Transaction Get(in byte[] transactionId);
    int Count();
}

/// <summary>
/// 
/// </summary>
public enum StakeType
{
    System = 0x00,
    Node = 0x01
}

/// <summary>
/// </summary>
internal record CoinStake
{
    public Transaction Transaction { get; init; }
    public ulong Solution { get; init; }
    public uint StakeAmount { get; init; }
}

/// <summary>
/// </summary>
internal record Kernel
{
    public byte[] CalculatedVrfSignature { get; init; }
    public byte[] Hash { get; init; }
    public byte[] VerifiedVrfSignature { get; init; }
    public StakeType StakeType { get; init; }
}

/// <summary>
/// 
/// </summary>
internal record ReadyTransaction
{
    public byte[] PrivateKey { get; init; }
    public byte[] PublicKey { get; init; }
    public byte[] PrevBlockHash { get; init; }
    public byte[] PrevVrfSig { get; init; }
    public ulong Round { get; init; }
}

/// <summary>
/// </summary>
public class PPoS : IPPoS, IDisposable
{
    private readonly ISystemCore _systemCore;
    private readonly ILogger _logger;
    private readonly Caching<Transaction> _syncCacheTransactions = new();
    private readonly IDisposable _stakeDisposable;
    private bool _disposed;
    private int _running;

    /// <summary>
    /// </summary>
    /// <param name="systemCore"></param>
    /// <param name="logger"></param>
    public PPoS(ISystemCore systemCore, ILogger logger)
    {
        _systemCore = systemCore;
        _logger = logger.ForContext("SourceContext", nameof(PPoS));
        _stakeDisposable = Observable.Interval(TimeSpan.FromSeconds(LedgerConstant.BlockProposalTimeFromSeconds))
            .SubscribeOn(Scheduler.Default)
            .Subscribe(async _ => await InitAsync());
    }

    /// <summary>
    /// </summary>
    public bool Running => _running != 0;

    /// <summary>
    /// </summary>
    /// <param name="transactionId"></param>
    /// <returns></returns>
    public Transaction Get(in byte[] transactionId)
    {
        Guard.Argument(transactionId, nameof(transactionId)).NotNull().NotEmpty().MaxCount(32);
        try
        {
            if (_syncCacheTransactions.TryGet(transactionId, out var transaction))
                return transaction;
        }
        catch (Exception ex)
        {
            _logger.Here().Error(ex, "Unable to find transaction {@TxId}", transactionId.ByteToHex());
        }

        return null;
    }

    /// <summary>
    /// </summary>
    /// <returns></returns>
    public int Count()
    {
        return _syncCacheTransactions.Count;
    }

    /// <summary>
    /// </summary>
    private async Task InitAsync()
    {
        if (_systemCore.ApplicationLifetime.ApplicationStopping.IsCancellationRequested) return;
        var sync = _systemCore.Sync();
        if (sync.Running)
        {
            Thread.Sleep(TimeSpan.FromSeconds(LedgerConstant.WaitSyncTimeFromSeconds));
            return;
        }

        if (!_systemCore.Node.Staking.Enabled)
        {
            Thread.Sleep(TimeSpan.FromSeconds(LedgerConstant.WaitPPoSEnabledTimeFromSeconds));
            return;
        }

        if (sync.Running) return;
        //if (!_systemCore.Graph().RoundCompleted) return;
        if (Running) return;
        Interlocked.Exchange(ref _running, 1);
        await RunStakingAsync();
    }

    /// <summary>
    /// </summary>
    /// <exception cref="Exception"></exception>
    private async Task RunStakingAsync()
    {
        try
        {
            var prevBlock = await _systemCore.Validator().PreviousBlockAdjustedTimeAsync();
            if (prevBlock is null) return;
            if (!await _systemCore.Graph().BlockCountSynchronizedAsync())
            {
                return;
            }
            await PullMempoolTransactionsAsync();
            if (_syncCacheTransactions.Count == 0) return;
            var height = prevBlock.Height + 1;
            var readyTransaction = new ReadyTransaction
            {
                PrevBlockHash = prevBlock.Hash,
                Round = height,
                PrevVrfSig = prevBlock.BlockPos.VrfSig,
                PrivateKey = _systemCore.KeyPair.PrivateKey.FromSecureString().HexToByte(),
                PublicKey = _systemCore.KeyPair.PublicKey
            };
            var kernel = CreateNetworkKernel(readyTransaction, StakeType.Node);
            if (kernel is null) return;

            CoinStake coinStake;
            if (_systemCore.Validator()
                    .VerifyKernel(await _systemCore.Validator().NodeKernelAsync(kernel.VerifiedVrfSignature, height),
                        kernel.Hash) == VerifyResult.Succeed)
            {
                _logger.Information("KERNEL <selected> for round [{@Round}]", height);
                coinStake = await CoinstakeAsync(kernel);
                if (coinStake is null) return;
                RemoveAnyCoinstake();
            }
            else
            {
                _logger.Information("SYSTEM KERNEL <selected> for round [{@Round}]", height); // prev round + current + next round
                kernel = CreateNetworkKernel(readyTransaction, StakeType.System);
                if (kernel is null) return;
                coinStake = CoinstakeSystem(height);
                if (coinStake is null) return;
            }
            _syncCacheTransactions.Add(coinStake.Transaction.TxnId, coinStake.Transaction);
            var transactions = SortTransactions();
            var newBlock = await NewBlockAsync(transactions, kernel, coinStake, prevBlock);
            if (newBlock is null) return;
            var blockGraph = NewBlockGraph(in newBlock, in prevBlock);
            if (blockGraph is null) return;
            var graph = _systemCore.Graph();
            if (await graph.BlockHeightExistsAsync(new BlockHeightExistsRequest(newBlock.Height)) ==
                VerifyResult.AlreadyExists) return;
            foreach (var transaction in transactions) _syncCacheTransactions.Remove(transaction.TxnId);
            _logger.Information("Publishing... [BLOCKGRAPH]");
            await graph.PostAsync(blockGraph);
        }
        catch (Exception ex)
        {
            _logger.Here().Error(ex, "Pure Proof of Stake failed");
        }
        finally
        {
            // Call again in case of an exception.
            RemoveAnyCoinstake();
            Interlocked.Exchange(ref _running, 0);
        }
    }

    /// <summary>
    /// </summary>
    /// <returns></returns>
    private ImmutableArray<Transaction> SortTransactions()
    {
        var transactions = _syncCacheTransactions.GetItems();
        if (transactions.Length == 0) return ImmutableArray<Transaction>.Empty;
        if (transactions[0].Vtime == null) return transactions.ToArray().ToImmutableArray();
        var n = transactions.Length;
        var aux = new Transaction[n];
        for (var i = 0; i < n; i++) aux[i] = transactions.ElementAt(n - 1 - i);
        return aux.ToImmutableArray();
    }

    /// <summary>
    /// Sanity check if coinstake transaction exists before adding.
    /// </summary>
    private void RemoveAnyCoinstake()
    {
        try
        {
            foreach (var transaction in _syncCacheTransactions.GetItems())
            {
                if (transaction.OutputType() != CoinType.Coinstake) continue;
                _logger.Warning("Removing coinstake transaction");
                _syncCacheTransactions.Remove(transaction.TxnId);
            }
        }
        catch (Exception)
        {
            // Ignore
        }
    }

    /// <summary>
    /// 
    /// </summary>
    private async Task PullMempoolTransactionsAsync()
    {
        var memPool = _systemCore.MemPool();
        var verifiedTransactions = Array.Empty<Transaction>();
        if (_syncCacheTransactions.Count < _systemCore.Node.Staking.MaxTransactionsPerBlock)
            verifiedTransactions = await memPool.GetVerifiedTransactionsAsync(
                _systemCore.Node.Staking.MaxTransactionsPerBlock - _syncCacheTransactions.Count);
        var txsSize = 0;
        foreach (var transaction in verifiedTransactions)
        {
            txsSize += transaction.GetSize();
            if (txsSize <= _systemCore.Node.Staking.MaxTransactionSizePerBlock)
            {
                _syncCacheTransactions.Add(transaction.TxnId, transaction);
            }
        }

        if (verifiedTransactions.Length > 0)
        {
            _logger.Information("PROOF-OF-STAKE <transactions>      [{@Count}]", Count());
        }
        RemoveAnyDuplicateImageKeys();
        await RemoveAnyUnVerifiedTransactionsAsync();
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="readyTransaction"></param>
    /// <param name="stakeType"></param>
    /// <returns></returns>
    private Kernel CreateNetworkKernel(ReadyTransaction readyTransaction, StakeType stakeType)
    {
        var kernel = _systemCore.Validator().NetworkKernel(readyTransaction.PrevBlockHash,
            Hasher.Hash(readyTransaction.PrevVrfSig).HexToByte(), readyTransaction.Round);
        var crypto = _systemCore.Crypto();
        var calculatedVrfSignature = crypto.GetCalculateVrfSignature(
            Curve.decodePrivatePoint(readyTransaction.PrivateKey), kernel);
        var verifyVrfSignature = crypto.GetVerifyVrfSignature(
            Curve.decodePoint(readyTransaction.PublicKey, 0), kernel, calculatedVrfSignature);
        return new Kernel
        {
            CalculatedVrfSignature = calculatedVrfSignature,
            Hash = kernel,
            VerifiedVrfSignature = verifyVrfSignature,
            StakeType = stakeType
        };
    }

    /// <summary>
    /// 
    /// </summary>
    private void RemoveAnyDuplicateImageKeys()
    {
        var noDupImageKeys = new List<byte[]>();
        foreach (var transaction in _syncCacheTransactions.GetItems())
            foreach (var vin in transaction.Vin)
            {
                var vInput = noDupImageKeys.FirstOrDefault(x => x.Xor(vin.Image));
                if (vInput is not null) _syncCacheTransactions.Remove(transaction.TxnId);
                noDupImageKeys.Add(vin.Image);
            }
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="previous"></param>
    /// <param name="next"></param>
    /// <returns></returns>
    private static byte[] IncrementHasher(byte[] previous, byte[] next)
    {
        Guard.Argument(previous, nameof(previous)).NotNull().MaxCount(32);
        Guard.Argument(next, nameof(next)).NotNull().MaxCount(32);
        var hasher = Hasher.New();
        hasher.Update(previous);
        hasher.Update(next);
        var hash = hasher.Finalize();
        return hash.AsSpanUnsafe().ToArray();
    }

    /// <summary>
    /// </summary>
    /// <param name="kernel"></param>
    /// <returns></returns>
    /// <exception cref="Exception"></exception>
    private async Task<CoinStake> CoinstakeAsync(Kernel kernel)
    {
        Guard.Argument(kernel, nameof(kernel)).NotNull();
        _logger.Information("Begin...      [SOLUTION]");
        var validator = _systemCore.Validator();
        var solution = new BigInteger(1, Hasher.Hash(kernel.VerifiedVrfSignature).HexToByte());
        var calculatedSolution = solution.Mod(new BigInteger(1, LedgerConstant.MBits.ToBytes()));
        var cS = Convert.ToUInt64(calculatedSolution.ToString());
        var networkShare = validator.NetworkShare(cS, _systemCore.UnitOfWork().HashChainRepository.Count + 1);
        var bits = validator.Bits(cS, networkShare);
        _logger.Information("Begin...      [COINSTAKE]");
        var walletTransaction = await _systemCore.Wallet().CreateTransactionAsync(bits, networkShare.ConvertToUInt64(),
            _systemCore.Node.Staking.RewardAddress);
        if (walletTransaction.Transaction is not null)
            return new CoinStake { StakeAmount = bits, Transaction = walletTransaction.Transaction, Solution = cS };
        _logger.Warning("Unable to create coinstake transaction: {@Message}", walletTransaction.Message);
        return null;
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="block"></param>
    /// <param name="prevBlock"></param>
    /// <returns></returns>
    private BlockGraph NewBlockGraph(in Block block, in Block prevBlock)
    {
        Guard.Argument(block, nameof(block)).NotNull();
        Guard.Argument(prevBlock, nameof(prevBlock)).NotNull();
        _logger.Information("Begin...      [BLOCKGRAPH]");
        try
        {
            var nodeIdentifier = _systemCore.NodeId();
            var nextData = block.Serialize();
            var nextDataHash = Hasher.Hash(nextData);
            var blockGraph = new BlockGraph
            {
                Block = new Consensus.Models.Block
                {
                    BlockHash = block.Hash,
                    Data = nextData,
                    DataHash = nextDataHash.ToString(),
                    Hash = Hasher.Hash(block.Height.ToBytes()).ToString(),
                    Node = nodeIdentifier,
                    Round = block.Height
                },
                Prev = new Consensus.Models.Block
                {
                    BlockHash = prevBlock.Hash,
                    Data = Array.Empty<byte>(),
                    DataHash = string.Empty,
                    Hash = Hasher.Hash(prevBlock.Height.ToBytes()).ToString(),
                    Node = nodeIdentifier,
                    Round = prevBlock.Height
                }
            };

            return blockGraph;
        }
        catch (Exception)
        {
            _logger.Here().Error("Unable to create new blockgraph");
        }

        return null;
    }

    /// <summary>
    /// </summary>
    /// <param name="transactions"></param>
    /// <param name="kernel"></param>
    /// <param name="coinStake"></param>
    /// <param name="previousBlock"></param>
    /// <returns></returns>
    private async Task<Block> NewBlockAsync(ImmutableArray<Transaction> transactions, Kernel kernel, CoinStake coinStake,
        Block previousBlock)
    {
        Guard.Argument(transactions, nameof(transactions)).NotEmpty();
        Guard.Argument(kernel, nameof(kernel)).NotNull();
        Guard.Argument(kernel.CalculatedVrfSignature, nameof(kernel.CalculatedVrfSignature)).NotNull().MaxCount(96);
        Guard.Argument(kernel.VerifiedVrfSignature, nameof(kernel.VerifiedVrfSignature)).NotNull().MaxCount(32);
        Guard.Argument(coinStake, nameof(coinStake)).NotNull();
        Guard.Argument(coinStake.Solution, nameof(coinStake.Solution)).NotZero().NotNegative();
        Guard.Argument(coinStake.StakeAmount, nameof(coinStake.StakeAmount)).NotNegative();
        Guard.Argument(previousBlock, nameof(previousBlock)).NotNull();
        _logger.Information("Begin...      [BLOCK]");
        try
        {
            var height = previousBlock.Height + 1;
            var merkelRoot = BlockHeader.ToMerkleRoot(previousBlock.BlockHeader.MerkleRoot, transactions);
            var lockTime = Util.GetAdjustedTimeAsUnixTimestamp(LedgerConstant.BlockProposalTimeFromSeconds);
            var nonce = await GetNonceAsync(kernel.VerifiedVrfSignature, coinStake.Solution, height,
                lockTime);
            if (nonce.Length == 0) return null;
            var block = new Block
            {
                Hash = new byte[32],
                Height = height,
                BlockHeader = new BlockHeader
                {
                    Height = height,
                    Locktime = lockTime,
                    LocktimeScript =
                        new Script(Op.GetPushOp(lockTime), OpcodeType.OP_CHECKLOCKTIMEVERIFY).ToString().ToBytes(),
                    MerkleRoot = merkelRoot,
                    PrevBlockHash = previousBlock.Hash
                },
                NrTx = (ushort)transactions.Length,
                Txs = transactions.ToArray(),
                BlockPos = new BlockPoS
                {
                    StakeAmount = coinStake.StakeAmount,
                    Nonce = nonce,
                    Solution = coinStake.Solution,
                    VrfProof = kernel.CalculatedVrfSignature,
                    VrfSig = kernel.VerifiedVrfSignature,
                    PublicKey = _systemCore.KeyPair.PublicKey,
                    StakeType = kernel.StakeType
                },
                Size = 1
            };

            block.Size = block.GetSize();
            block.Hash = IncrementHasher(previousBlock.Hash, block.ToHash());
            return block;
        }
        catch (Exception ex)
        {
            _logger.Here().Error(ex, "Unable to create new block");
        }

        return null;
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="solution"></param>
    /// <param name="vrfOutput"></param>
    /// <param name="round"></param>
    /// <param name="lockTime"></param>
    /// <returns></returns>
    private async Task<byte[]> GetNonceAsync(byte[] vrfOutput, ulong solution, ulong round, long lockTime)
    {
        Guard.Argument(vrfOutput, nameof(vrfOutput)).NotNull().NotEmpty().MaxCount(32);
        Guard.Argument(solution, nameof(solution)).NotZero();
        Guard.Argument(lockTime, nameof(lockTime)).NotNegative().NotZero();
        _logger.Information("Begin...      [SLOTH]");
        var transactions = SortTransactions();
        if (_systemCore.Graph().HashTransactions(new HashTransactionsRequest(transactions.ToArray())) is not
            { } transactionsHash) return null;
        var x = Numerics.BigInteger.Parse(Util.SlothEvalT(transactionsHash, vrfOutput, round, lockTime).ByteToHex(),
            NumberStyles.AllowHexSpecifier);
        if (x.Sign <= 0) x = -x;
        var nonceHash = Array.Empty<byte>();
        try
        {
            var sloth = new Sloth(PrimeBit.P256, LedgerConstant.SlothCancellationTimeoutFromMilliseconds,
                _systemCore.ApplicationLifetime.ApplicationStopping);
            var nonce = await sloth.EvalAsync((int)solution / LedgerConstant.CalculateTimeCost(transactions.Length), x);
            if (!string.IsNullOrEmpty(nonce)) nonceHash = nonce.ToBytes();
        }
        catch (Exception ex)
        {
            _logger.Here().Error("{@Message}", ex.Message);
        }

        return nonceHash;
    }

    /// <summary>
    ///  Removes any transactions already on chain or are invalid.
    /// </summary>
    /// <returns></returns>
    private async Task RemoveAnyUnVerifiedTransactionsAsync()
    {
        var validator = _systemCore.Validator();
        foreach (var transaction in _syncCacheTransactions.GetItems())
        {
            if (transaction.OutputType() == CoinType.Coinstake) continue;
            if (await validator.VerifyTransactionAsync(transaction) != VerifyResult.Succeed)
                _syncCacheTransactions.Remove(transaction.TxnId);
        }
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="round"></param>
    /// <returns></returns>
    private CoinStake CoinstakeSystem(ulong round)
    {
        var r = round.ToBytes().WrapLengthPrefix();
        var tx = new Transaction
        {
            Bp = Array.Empty<Bp>(),
            Rct = Array.Empty<Rct>(),
            Vin = Array.Empty<Vin>(),
            Vout = new[]
            {
                new Vout
                {
                    A = 0,
                    C = new byte[33],
                    E = new byte[33],
                    N = new byte[r.Length + 64],
                    P = new byte[33],
                    T = CoinType.System
                }
            }
        };
        Buffer.BlockCopy(r, 0, tx.Vout[0].N, 0, r.Length);
        var sig = _systemCore.Crypto()
            .SignXEdDSA(_systemCore.KeyPair.PrivateKey.FromSecureString().HexToByte(), tx.ToHash());
        tx.Vout[0].N = Util.Combine(r, sig);
        tx.TxnId = tx.ToHash();
        return new CoinStake { Solution = LedgerConstant.SystemSolutionTime, Transaction = tx };
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
            _stakeDisposable.Dispose();
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