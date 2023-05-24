// Tangram by Matthew Hellyer is licensed under CC BY-NC-ND 4.0.
// To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Blake3;
using TangramXtgm.Extensions;
using Dawn;
using Libsecp256k1Zkp.Net;
using libsignal.ecc;
using NBitcoin;
using NBitcoin.BouncyCastle.Math;
using Serilog;
using TangramXtgm.Consensus.Models;
using TangramXtgm.Cryptography;
using TangramXtgm.Models;
using TangramXtgm.Models.Messages;
using Block = TangramXtgm.Models.Block;
using BlockHeader = TangramXtgm.Models.BlockHeader;
using Transaction = TangramXtgm.Models.Transaction;
using Numerics = System.Numerics;

namespace TangramXtgm.Ledger;

/// <summary>
/// </summary>
public interface IValidator
{
    VerifyResult VerifyBlockGraphNodeRound(ref BlockGraph blockGraph);
    VerifyResult VerifyBulletProof(Vout[] vOutputs, Bp[] bulletProofs);
    Task<VerifyResult> VerifyCoinbaseTransactionAsync(Vout coinbase, ulong solution, ulong height, long lockTime);
    VerifyResult VerifySystemCoinbase(Transaction tx, byte[] publicKey, ulong height);
    VerifyResult VerifySolution(BlockPoS blockPoS);
    Task<VerifyResult> VerifyBlockAsync(Block block);
    Task<VerifyResult> VerifyBlocksAsync(Block[] blocks);
    Task<VerifyResult> VerifyTransactionAsync(Transaction transaction);
    Task<VerifyResult> VerifyTransactionsAsync(IList<Transaction> transactions);
    VerifyResult VerifySloth(uint t, byte[] message, byte[] nonce);
    VerifyResult VerifySloth(Block block);
    uint Bits(ulong solution, decimal networkShare);
    decimal NetworkShare(ulong solution, ulong height);
    VerifyResult VerifyKernel(byte[] vrfOutput, byte[] kernel);
    VerifyResult VerifyLockTime(LockTime target, byte[] script);
    VerifyResult VerifyCommit(Vout[] vOutputs);
    Task<VerifyResult> VerifyKeyImageNotReusedAsync(Transaction transaction);
    Task<VerifyResult> VerifyKeyImageNotReusedAsync(byte[] image);
    Task<VerifyResult> VerifyOnetimeKeyNotReusedAsync(Transaction transaction);
    Task<VerifyResult> VerifyCommitmentOutputsAsync(Transaction transaction);
    Task<decimal> CurrentRunningDistributionAsync(ulong solution, ulong height);
    Task<decimal> RunningDistributionAsync();
    VerifyResult VerifyNetworkShare(ulong solution, decimal previousNetworkShare, decimal runningDistributionTotal, ulong height);
    Task<VerifyResult> VerifyBlockHashAsync(Block block);
    Task<VerifyResult> VerifyMerkleAsync(Block block);
    VerifyResult VerifyTransactionTime(Transaction transaction);
    byte[] NetworkKernel(byte[] prevHash, byte[] hash, ulong round);
    Task<Block[]> ForkRuleAsync(Block[] xChain);
    VerifyResult VerifyMlsag(Transaction transaction);
    VerifyResult VerifyTransactionsWithNoDuplicateKeys(Transaction[] transactions);
    VerifyResult VerifyBlocksWithNoDuplicateHeights(IReadOnlyList<Block> blocks);
    Task<Block> PreviousBlockAdjustedTimeAsync();
    byte[] MembershipProof(byte[] prevMerkelRoot, byte[] txStream, int index, Transaction[] transactions);
    public Task<byte[]> NodeKernelAsync(byte[] vrfOutput, ulong round);
}

/// <summary>
/// </summary>
public class Validator : IValidator
{
    private readonly ISystemCore _systemCore;
    private readonly ILogger _logger;

    /// <summary>
    /// </summary>
    /// <param name="systemCore"></param>
    /// <param name="logger"></param>
    public Validator(ISystemCore systemCore, ILogger logger)
    {
        _systemCore = systemCore;
        _logger = logger.ForContext("SourceContext", nameof(Validator));
    }

    /// <summary>
    /// </summary>
    /// <param name="block"></param>
    /// <returns></returns>
    public async Task<VerifyResult> VerifyBlockHashAsync(Block block)
    {
        Guard.Argument(block, nameof(block)).NotNull();
        var prevBlock = await _systemCore.Graph().GetPreviousBlockAsync();
        if (prevBlock is null) return VerifyResult.UnableToVerify;
        using var hasher = Hasher.New();
        hasher.Update(prevBlock.Hash);
        hasher.Update(block.ToHash());
        var hash = hasher.Finalize();
        var verifyHasher = hash.AsSpanUnsafe().ToArray().Xor(block.Hash);
        return verifyHasher ? VerifyResult.Succeed : VerifyResult.UnableToVerify;
    }

    /// <summary>
    /// </summary>
    /// <param name="block"></param>
    /// <returns></returns>
    public async Task<VerifyResult> VerifyMerkleAsync(Block block)
    {
        Guard.Argument(block, nameof(block)).NotNull();

        var prevBlock = await _systemCore.Graph().GetPreviousBlockAsync();
        if (prevBlock is null) return VerifyResult.UnableToVerify;
        var merkelRoot =
            BlockHeader.ToMerkleRoot(prevBlock.BlockHeader.MerkleRoot, block.Txs.ToImmutableArray());
        var verifyMerkel = merkelRoot.Xor(block.BlockHeader.MerkleRoot);
        return verifyMerkel ? VerifyResult.Succeed : VerifyResult.UnableToVerify;
    }

    /// <summary>
    /// </summary>
    /// <param name="blockGraph"></param>
    /// <returns></returns>
    public VerifyResult VerifyBlockGraphNodeRound(ref BlockGraph blockGraph)
    {
        Guard.Argument(blockGraph, nameof(blockGraph)).NotNull();
        var blockGraphRef = blockGraph;
        try
        {
            if (blockGraphRef.Prev == null) return VerifyResult.UnableToVerify;
            if (blockGraphRef.Prev.Round != 0)
            {
                if (blockGraphRef.Prev.Node != blockGraphRef.Block.Node)
                {
                    _logger.Error("Previous block node does not match block {@Round} from node {@Node}",
                        blockGraphRef.Block.Round, blockGraphRef.Block.Node);
                    return VerifyResult.UnableToVerify;
                }

                if (blockGraphRef.Prev.Round + 1 != blockGraphRef.Block.Round)
                {
                    _logger.Error("Previous block round is invalid on block {@Round} from node {@Node}",
                        blockGraphRef.Block.Round, blockGraphRef.Block.Node);
                    return VerifyResult.UnableToVerify;
                }
            }

            if (blockGraphRef.Dependencies.Any(dep => dep.Block.Node == blockGraphRef.Block.Node))
            {
                _logger.Error(
                    "Block references includes a block from the same node in block {@Round} from node {@Node}",
                    blockGraphRef.Block.Round, blockGraphRef.Block.Node);
                return VerifyResult.UnableToVerify;
            }
        }
        catch (Exception ex)
        {
            _logger.Here().Error(ex, "Unable to verify block graph signature");
            return VerifyResult.UnableToVerify;
        }

        return VerifyResult.Succeed;
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="vOutputs"></param>
    /// <param name="bulletProofs"></param>
    /// <returns></returns>
    public VerifyResult VerifyBulletProof(Vout[] vOutputs, Bp[] bulletProofs)
    {
        Guard.Argument(vOutputs, nameof(vOutputs)).NotNull().NotEmpty();
        Guard.Argument(bulletProofs, nameof(bulletProofs)).NotNull().NotEmpty();
        try
        {
            using var secp256K1 = new Secp256k1();
            using var bulletProof = new BulletProof();
            var commitments = vOutputs.Where(x => x.T is CoinType.Change or CoinType.Mint).ToArray();
            foreach (var (bp, i) in bulletProofs.WithIndex())
            {
                if (bulletProof.Verify(commitments[i].C, bp.Proof, null!)) continue;
                _logger.Fatal("Unable to verify the bullet proof");
                return VerifyResult.UnableToVerify;
            }
        }
        catch (Exception ex)
        {
            _logger.Here().Error("{@Message}", ex.Message);
            return VerifyResult.UnableToVerify;
        }

        return VerifyResult.Succeed;
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="vOutputs"></param>
    /// <returns></returns>
    public VerifyResult VerifyCommit(Vout[] vOutputs)
    {
        Guard.Argument(vOutputs, nameof(vOutputs)).NotNull().NotEmpty();
        try
        {
            using var pedersen = new Pedersen();
            var vCount = vOutputs.Length;
            var index = 0;
            while (vCount != 0)
            {
                if (vOutputs[index].T == CoinType.Coinbase)
                {
                    if (vOutputs[index].D is null)
                    {
                        _logger.Fatal("Unable to verify the blind");
                        return VerifyResult.UnableToVerify;
                    }

                    var reward = vOutputs[index].A;
                    var coinbase = vOutputs[index].C;
                    var blind = vOutputs[index].D;
                    var commit = pedersen.Commit(reward, blind);
                    if (!commit.Xor(coinbase))
                    {
                        _logger.Fatal("Unable to verify coinbase commitment");
                        return VerifyResult.UnableToVerify;
                    }

                    index++;
                    var payout = vOutputs[index].A;
                    var coinstake = vOutputs[index].C;
                    blind = vOutputs[index].D;
                    commit = pedersen.Commit(payout, blind);
                    if (!commit.Xor(coinstake))
                    {
                        _logger.Fatal("Unable to verify coinstake commitment");
                        return VerifyResult.UnableToVerify;
                    }
                }

                if (vOutputs[index].T == CoinType.Mint)
                {
                    var commitments = vOutputs.Where(x => x.T == CoinType.Burn).Select(x => x.C).ToList();
                    if (!pedersen.VerifyCommitSum(new List<byte[]> { vOutputs[index].C }, commitments))
                    {
                        _logger.Fatal("Unable to verify mint committed sum");
                        return VerifyResult.UnableToVerify;
                    }

                    if (vOutputs.Last().T != CoinType.Mint)
                    {
                        _logger.Fatal("Unable to verify last mint type");
                        return VerifyResult.UnableToVerify;
                    }

                    break;
                }

                var payment = vOutputs[index].C;
                index++;
                var change = vOutputs[index].C;
                var commitSumBalance = pedersen.CommitSum(new List<byte[]> { payment, change }, new List<byte[]>());
                if (pedersen.VerifyCommitSum(new List<byte[]> { commitSumBalance },
                        new List<byte[]> { payment, change }))
                {
                    index++;
                    if (vCount == index) break;
                    continue;
                }

                _logger.Fatal("Unable to verify committed sum");
                return VerifyResult.UnableToVerify;
            }
        }
        catch (Exception ex)
        {
            _logger.Here().Error(ex, "Unable to verify the committed sum");
            return VerifyResult.UnableToVerify;
        }

        return VerifyResult.Succeed;
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="blockPoS"></param>
    /// <returns></returns>
    public VerifyResult VerifySolution(BlockPoS blockPoS)
    {
        Guard.Argument(blockPoS, nameof(blockPoS)).NotNull();
        var isSolution = false;

        try
        {
            if (LedgerConstant.SolutionThrottle > blockPoS.Solution)
            {
                var solution = _systemCore.UnitOfWork().HashChainRepository.Count >= LedgerConstant.BlockV3Height
                    ? new BigInteger(1, Hasher.Hash(blockPoS.VrfSig).HexToByte())
                    : new BigInteger(1, blockPoS.VrfProof);
                var calculatedSolution = solution.Mod(new BigInteger(1, LedgerConstant.MBits.ToBytes()));
                var cS = Convert.ToUInt64(calculatedSolution.ToString());
                isSolution = cS == blockPoS.Solution;
            }
        }
        catch (Exception ex)
        {
            _logger.Here().Error(ex, "Unable to verify solution");
        }

        return isSolution ? VerifyResult.Succeed : VerifyResult.UnableToVerify;
    }

    /// <summary>
    /// </summary>
    /// <param name="blocks"></param>
    /// <returns></returns>
    public async Task<VerifyResult> VerifyBlocksAsync(Block[] blocks)
    {
        Guard.Argument(blocks, nameof(blocks)).NotNull().NotEmpty();
        foreach (var block in blocks)
        {
            if (await VerifyBlockAsync(block) == VerifyResult.Succeed) continue;
            _logger.Fatal("Unable to verify the block");
            return VerifyResult.UnableToVerify;
        }

        return VerifyResult.Succeed;
    }

    /// <summary>
    /// </summary>
    /// <param name="block"></param>
    /// <returns></returns>
    public async Task<VerifyResult> VerifyBlockAsync(Block block)
    {
        Guard.Argument(block, nameof(block)).NotNull();
        if (VerifyLockTime(new LockTime(Utils.UnixTimeToDateTime(block.BlockHeader.Locktime)),
                block.BlockHeader.LocktimeScript) != VerifyResult.Succeed)
        {
            _logger.Fatal("Unable to verify the block lock time");
            return VerifyResult.UnableToVerify;
        }

        if (block.Txs.First().Vout.First().T == CoinType.System)
        {
            if (VerifySystemCoinbase(block.Txs.First(), block.BlockPos.PublicKey, block.Height) != VerifyResult.Succeed)
            {
                _logger.Fatal("Unable to verify system coinbase transaction");
                return VerifyResult.UnableToVerify;
            }
        }
        else
        {
            var kernel = await KernelAsync(block);
            if (kernel is null)
            {
                _logger.Fatal("Unable to verify kernel");
                return VerifyResult.UnableToVerify;
            }
            if (await VerifyNodeCoinbaseAsync(block, kernel) != VerifyResult.Succeed)
            {
                _logger.Fatal("Unable to verify node coinbase transaction");
                return VerifyResult.UnableToVerify;
            }
        }

        if (block.BlockHeader.MerkleRoot.Xor(LedgerConstant.BlockZeroMerkel) &&
            block.BlockHeader.PrevBlockHash.Xor(LedgerConstant.BlockZeroPrevHash)) return VerifyResult.Succeed;
        if (await PreviousBlockAdjustedTimeAsync() is null)
        {
            _logger.Fatal("Unable to verify the block time");
            return VerifyResult.UnableToVerify;
        }

        if (VerifySloth(block) != VerifyResult.Succeed)
        {
            _logger.Here().Fatal("Unable to verify the slow function");
            return VerifyResult.UnableToVerify;
        }

        if (await VerifyBlockHashAsync(block) != VerifyResult.Succeed)
        {
            _logger.Fatal("Unable to verify the block hash");
            return VerifyResult.UnableToVerify;
        }

        if (await VerifyMerkleAsync(block) != VerifyResult.Succeed)
        {
            _logger.Fatal("Unable to verify the merkel tree");
            return VerifyResult.UnableToVerify;
        }

        if (VerifyTransactionsWithNoDuplicateKeys(block.Txs.ToArray()) != VerifyResult.Succeed)
        {
            _logger.Fatal("Unable to verify transactions with duplicate keys");
            return VerifyResult.UnableToVerify;
        }

        if (await VerifyTransactionsAsync(block.Txs) == VerifyResult.Succeed) return VerifyResult.Succeed;
        _logger.Fatal("Unable to verify the block transactions");
        return VerifyResult.UnableToVerify;
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="block"></param>
    /// <returns></returns>
    private async Task<byte[]> KernelAsync(Block block)
    {
        Guard.Argument(block, nameof(block)).NotNull();
        byte[] kernel;
        if (_systemCore.UnitOfWork().HashChainRepository.Count >= LedgerConstant.BlockV3Height)
        {
            var prevBlock = await _systemCore.Graph().GetPreviousBlockAsync();
            kernel = NetworkKernel(prevBlock.Hash, Hasher.Hash(prevBlock.BlockPos.VrfSig).HexToByte(), block.Height);
        }
        else
        {
            if (_systemCore.Graph().HashTransactions(
                    new HashTransactionsRequest(block.Txs.Skip(1).ToArray(block.Txs.Count - 1))) is not
                    { } transactionsHash)
            {
                _logger.Fatal("Unable to verify hashed transactions");
                return null;
            }

            kernel = NetworkKernel(block.BlockHeader.PrevBlockHash, transactionsHash, block.Height);
        }

        if (kernel is null)
            return null;

        if (_systemCore.Crypto()
            .GetVerifyVrfSignature(Curve.decodePoint(block.BlockPos.PublicKey, 0), kernel, block.BlockPos.VrfProof)
            .Xor(block.BlockPos.VrfSig)) return kernel;
        _logger.Fatal("Unable to verify Vrf signature with proof signature");
        return null;
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="block"></param>
    /// <param name="kernel"></param>
    /// <returns></returns>
    private async Task<VerifyResult> VerifyNodeCoinbaseAsync(Block block, byte[] kernel)
    {
        if (await VerifyCoinbaseTransactionAsync(block.Txs.First().Vout.First(), block.BlockPos.Solution,
                block.Height, block.BlockHeader.Locktime) != VerifyResult.Succeed)
        {
            _logger.Fatal("Unable to verify the coinbase transaction");
            return VerifyResult.UnableToVerify;
        }

        if (_systemCore.UnitOfWork().HashChainRepository.Count >= LedgerConstant.BlockV3Height)
        {
            if (VerifyKernel(await NodeKernelAsync(block.BlockPos.VrfSig, block.Height), kernel) !=
                VerifyResult.Succeed)
            {
                _logger.Fatal("Unable to verify kernel");
                return VerifyResult.UnableToVerify;
            }
        }
        else
        {
            if (VerifyKernel(block.BlockPos.VrfProof, kernel) != VerifyResult.Succeed)
            {
                _logger.Fatal("Unable to verify kernel");
                return VerifyResult.UnableToVerify;
            }
        }

        if (VerifySolution(block.BlockPos) != VerifyResult.Succeed)
        {
            _logger.Fatal("Unable to verify the solution");
            return VerifyResult.UnableToVerify;
        }

        var bits = Bits(block.BlockPos.Solution, block.Txs.First().Vout.First().A.DivCoin());
        if (block.BlockPos.StakeAmount == bits) return VerifyResult.Succeed;
        _logger.Fatal("Unable to verify the bits");
        return VerifyResult.UnableToVerify;
    }

    /// <summary>
    /// </summary>
    /// <param name="transactions"></param>
    /// <returns></returns>
    public async Task<VerifyResult> VerifyTransactionsAsync(IList<Transaction> transactions)
    {
        Guard.Argument(transactions, nameof(transactions)).NotNull().NotEmpty();
        foreach (var transaction in transactions)
        {
            if (await VerifyTransactionAsync(transaction) == VerifyResult.Succeed) continue;
            _logger.Fatal("Unable to verify the transaction");
            return VerifyResult.UnableToVerify;
        }

        return VerifyResult.Succeed;
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="t"></param>
    /// <param name="message"></param>
    /// <param name="nonce"></param>
    /// <returns></returns>
    public VerifyResult VerifySloth(uint t, byte[] message, byte[] nonce)
    {
        Guard.Argument(t, nameof(t)).NotNegative().NotZero();
        Guard.Argument(message, nameof(message)).NotNull().MaxCount(32);
        Guard.Argument(nonce, nameof(nonce)).NotNull().MaxCount(77);
        try
        {
            var ct = new CancellationTokenSource(TimeSpan.FromSeconds(1)).Token;
            var sloth = new Sloth(PrimeBit.P256, LedgerConstant.SlothCancellationTimeoutFromMilliseconds, ct);
            var x = Numerics.BigInteger.Parse(message.ByteToHex(), NumberStyles.AllowHexSpecifier);
            var y = Numerics.BigInteger.Parse(nonce.FromBytes());
            if (x.Sign <= 0) x = -x;
            var verifySloth = sloth.Verify(t, x, y);
            return verifySloth ? VerifyResult.Succeed : VerifyResult.UnableToVerify;
        }
        catch (Exception ex)
        {
            _logger.Here().Fatal(ex, "Unable to verify the slow function");
        }

        return VerifyResult.UnableToVerify;
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="block"></param>
    /// <returns></returns>
    public VerifyResult VerifySloth(Block block)
    {
        Guard.Argument(block, nameof(block)).NotNull();
        try
        {
            if (_systemCore.UnitOfWork().HashChainRepository.Count < LedgerConstant.BlockV3Height)
                return VerifySloth(
                    (uint)(block.BlockPos.Solution / (ulong)LedgerConstant.CalculateTimeCost(block.NrTx)),
                    block.BlockPos.VrfSig, block.BlockPos.Nonce);
            if (_systemCore.Graph().HashTransactions(new HashTransactionsRequest(block.Txs.ToArray())) is not
                { } transactionsHash) return VerifyResult.UnableToVerify;
            return VerifySloth((uint)(block.BlockPos.Solution / (ulong)LedgerConstant.CalculateTimeCost(block.NrTx)),
                Helper.Util.SlothEvalT(transactionsHash, block.BlockPos.VrfSig, block.Height,
                    block.BlockHeader.Locktime), block.BlockPos.Nonce);
        }
        catch (Exception ex)
        {
            _logger.Here().Fatal(ex, "Unable to verify the slow function");
        }

        return VerifyResult.UnableToVerify;
    }

    /// <summary>
    /// </summary>
    /// <param name="transaction"></param>
    /// <returns></returns>
    public async Task<VerifyResult> VerifyTransactionAsync(Transaction transaction)
    {
        Guard.Argument(transaction, nameof(transaction)).NotNull();
        if (transaction.HasErrors().Any())
        {
            _logger.Fatal("Unable to validate transaction");
            return VerifyResult.UnableToVerify;
        }

        var outputs = transaction.Vout.Select(x => Enum.GetName(x.T)).ToArray();
        if (outputs.Contains(Enum.GetName(CoinType.System))) return VerifyResult.Succeed;
        if (outputs.Contains(Enum.GetName(CoinType.Payment)) && outputs.Contains(Enum.GetName(CoinType.Change)) &&
            outputs.Contains(Enum.GetName(CoinType.Burn)) && outputs.Contains(Enum.GetName(CoinType.Mint)))
        {
            if (VerifyTransactionTime(transaction) != VerifyResult.Succeed) return VerifyResult.UnableToVerify;
        }

        if (await VerifyCommitmentOutputsAsync(transaction) != VerifyResult.Succeed) return VerifyResult.UnableToVerify;
        if (await VerifyOnetimeKeyNotReusedAsync(transaction) != VerifyResult.Succeed) return VerifyResult.UnableToVerify;
        if (await VerifyKeyImageNotReusedAsync(transaction) != VerifyResult.Succeed) return VerifyResult.KeyImageAlreadyExists;
        if (VerifyCommit(transaction.Vout) != VerifyResult.Succeed) return VerifyResult.UnableToVerify;
        if (VerifyBulletProof(transaction.Vout, transaction.Bp) != VerifyResult.Succeed) return VerifyResult.UnableToVerify;
        return VerifyMlsag(transaction);
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="transactions"></param>
    public VerifyResult VerifyTransactionsWithNoDuplicateKeys(Transaction[] transactions)
    {
        Guard.Argument(transactions, nameof(transactions)).NotNull().NotEmpty();
        try
        {
            var noDupKeys = new List<byte[]>();
            foreach (var transaction in transactions)
            {
                if (noDupKeys.FirstOrDefault(x => x.Xor(transaction.TxnId)) is not null)
                    return VerifyResult.AlreadyExists;
                noDupKeys.Add(transaction.TxnId);

                foreach (var bp in transaction.Bp)
                {
                    if (noDupKeys.FirstOrDefault(x => x.Xor(bp.Proof)) is not null) return VerifyResult.AlreadyExists;
                    noDupKeys.Add(bp.Proof);
                }

                foreach (var vin in transaction.Vin)
                {
                    if (noDupKeys.FirstOrDefault(x => x.Xor(vin.Image)) is not null) return VerifyResult.AlreadyExists;
                    noDupKeys.Add(vin.Image);
                }

                var outputs = transaction.Vout.Select(x => Enum.GetName(x.T)).ToArray();
                if (!outputs.Contains(Enum.GetName(CoinType.System)))
                {
                    foreach (var vout in transaction.Vout)
                    {
                        if (noDupKeys.FirstOrDefault(x => x.Xor(vout.C)) is not null) return VerifyResult.AlreadyExists;
                        noDupKeys.Add(vout.C);
                        if (vout.E.Length != 9 && !vout.E.Xor("OP_RETURN".ToBytes()))
                        {
                            if (noDupKeys.FirstOrDefault(x => x.Xor(vout.E)) is not null)
                                return VerifyResult.AlreadyExists;
                            noDupKeys.Add(vout.E);
                        }

                        if (noDupKeys.FirstOrDefault(x => x.Xor(vout.N)) is not null) return VerifyResult.AlreadyExists;
                        noDupKeys.Add(vout.N);
                        if (noDupKeys.FirstOrDefault(x => x.Xor(vout.P)) is not null) return VerifyResult.AlreadyExists;
                        noDupKeys.Add(vout.P);
                        if (vout.D.Length != 0)
                        {
                            if (noDupKeys.FirstOrDefault(x => x.Xor(vout.D)) is not null)
                                return VerifyResult.AlreadyExists;
                            noDupKeys.Add(vout.D);
                        }

                        if (vout.S.Length == 0) continue;
                        {
                            if (noDupKeys.FirstOrDefault(x => x.Xor(vout.S)) is not null)
                                return VerifyResult.AlreadyExists;
                            noDupKeys.Add(vout.S);
                        }
                    }
                }

                foreach (var rct in transaction.Rct)
                {
                    if (noDupKeys.FirstOrDefault(x => x.Xor(rct.P)) is not null) return VerifyResult.AlreadyExists;
                    noDupKeys.Add(rct.P);
                    if (noDupKeys.FirstOrDefault(x => x.Xor(rct.I)) is not null) return VerifyResult.AlreadyExists;
                    noDupKeys.Add(rct.I);
                    if (noDupKeys.FirstOrDefault(x => x.Xor(rct.M)) is not null) return VerifyResult.AlreadyExists;
                    noDupKeys.Add(rct.M);
                    if (noDupKeys.FirstOrDefault(x => x.Xor(rct.S)) is not null) return VerifyResult.AlreadyExists;
                    noDupKeys.Add(rct.S);
                }

                if (transaction.OutputType() == CoinType.Coinstake ||
                    transaction.OutputType() == CoinType.System) continue;
                if (noDupKeys.FirstOrDefault(x => x.Xor(transaction.Vtime.M)) is not null)
                    return VerifyResult.AlreadyExists;
                noDupKeys.Add(transaction.Vtime.M);
                if (noDupKeys.FirstOrDefault(x => x.Xor(transaction.Vtime.N)) is not null)
                    return VerifyResult.AlreadyExists;
                noDupKeys.Add(transaction.Vtime.N);
                if (noDupKeys.FirstOrDefault(x => x.Xor(transaction.Vtime.S)) is not null)
                    return VerifyResult.AlreadyExists;
                noDupKeys.Add(transaction.Vtime.S);
            }
        }
        catch (Exception)
        {
            _logger.Fatal("Unable to validate transactions with no duplicate keys check");
            return VerifyResult.UnableToVerify;
        }

        return VerifyResult.Succeed;
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="transaction"></param>
    /// <returns></returns>
    public VerifyResult VerifyMlsag(Transaction transaction)
    {
        Guard.Argument(transaction, nameof(transaction)).NotNull();
        using var mlsag = new MLSAG();
        var skip = 0;
        for (var i = 0; i < transaction.Vin.Length; i++)
        {
            var take = transaction.Vout[skip].T == CoinType.Coinbase ? 3 : 2;
            var m = GenerateMlSag(transaction.Rct[i].M, transaction.Vout.Skip(skip).Take(take).ToArray(),
                transaction.Vin[i].Offsets,
                transaction.Mix, 2);
            var verifyMlsag = mlsag.Verify(transaction.Rct[i].I, transaction.Mix, 2, m,
                transaction.Vin[i].Image, transaction.Rct[i].P, transaction.Rct[i].S);
            if (!verifyMlsag)
            {
                _logger.Fatal("Unable to verify the MLSAG transaction");
                return VerifyResult.UnableToVerify;
            }

            skip += take;
        }

        return VerifyResult.Succeed;
    }

    /// <summary>
    /// </summary>
    /// <param name="transaction"></param>
    /// <returns></returns>
    public VerifyResult VerifyTransactionTime(Transaction transaction)
    {
        Guard.Argument(transaction, nameof(transaction)).NotNull();
        try
        {
            if (transaction.HasErrors().Any()) return VerifyResult.UnableToVerify;
            if (VerifyLockTime(new LockTime(Utils.UnixTimeToDateTime(transaction.Vtime.L)), transaction.Vtime.S) !=
                VerifyResult.Succeed)
            {
                _logger.Fatal("Unable to verify the transaction lock time");
                return VerifyResult.UnableToVerify;
            }

            if (_systemCore.UnitOfWork().HashChainRepository.Count >= LedgerConstant.TransactionV3Height)
            {
                var size = ((uint)transaction.Vtime.K).ConvertFromUInt32();
                if (size != transaction.GetSize() * 0.001M)
                {
                    _logger.Fatal("Unable to verify the transaction size");
                    return VerifyResult.UnableToVerify;
                }
                var t =
                    (int)(transaction.Vtime.T * decimal.Round(size, 0, MidpointRounding.ToZero) * 600 * 1.5M);
                if (t != transaction.Vtime.I)
                {
                    _logger.Fatal("Unable to verify the transaction calculated time");
                    return VerifyResult.UnableToVerify;
                }
            }

            var w = TimeSpan.FromTicks(transaction.Vtime.W).TotalSeconds;
            if (w < LedgerConstant.TransactionDefaultTimeDelayFromSeconds) return VerifyResult.UnableToVerify;
            if (VerifySloth((uint)transaction.Vtime.I, transaction.Vtime.M, transaction.Vtime.N) !=
                VerifyResult.Succeed)
            {
                _logger.Fatal("Unable to verify the slow function for the transaction time");
                return VerifyResult.UnableToVerify;
            }
        }
        catch (Exception)
        {
            _logger.Here().Fatal("Unable to verify the transaction time");
            return VerifyResult.UnableToVerify;
        }

        return VerifyResult.Succeed;
    }

    /// <summary>
    /// </summary>
    /// <param name="coinbase"></param>
    /// <param name="solution"></param>
    /// <param name="height"></param>
    /// <param name="lockTime"></param>
    /// <returns></returns>
    public async Task<VerifyResult> VerifyCoinbaseTransactionAsync(Vout coinbase, ulong solution, ulong height, long lockTime)
    {
        Guard.Argument(coinbase, nameof(coinbase)).NotNull();
        Guard.Argument(lockTime, nameof(lockTime)).NotNegative().NotZero();
        if (coinbase.Validate().Any()) return VerifyResult.UnableToVerify;
        if (coinbase.T != CoinType.Coinbase) return VerifyResult.UnableToVerify;
        var runningDistribution = await CurrentRunningDistributionAsync(solution, height);
        if (VerifyNetworkShare(solution, coinbase.A.DivCoin(), runningDistribution, height) != VerifyResult.Succeed)
            return VerifyResult.UnableToVerify;
        var rewardLockTime = Helper.Util.UnixTimeToDateTime(coinbase.L);
        var blockLockTime = Helper.Util.UnixTimeToDateTime(lockTime);
        var timeSpan = rewardLockTime - blockLockTime;
        if (timeSpan.Ticks < 862000000000) return VerifyResult.UnableToVerify; // 2 min grace
        using var pedersen = new Pedersen();
        var commit = pedersen.Commit(coinbase.A, coinbase.D);
        return commit.Xor(coinbase.C) ? VerifyResult.Succeed : VerifyResult.UnableToVerify;
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="tx"></param>
    /// <param name="publicKey"></param>
    /// <param name="height"></param>
    /// <returns></returns>
    public VerifyResult VerifySystemCoinbase(Transaction tx, byte[] publicKey, ulong height)
    {
        if (tx.Mix != 22) return VerifyResult.UnableToVerify;
        if (tx.Vout.Length != 1) return VerifyResult.UnableToVerify;
        if (tx.Vtime != null) return VerifyResult.UnableToVerify;
        if (tx.Bp.Length != 0) return VerifyResult.UnableToVerify;
        if (tx.Vin.Length != 0) return VerifyResult.UnableToVerify;
        if (tx.Rct.Length != 0) return VerifyResult.UnableToVerify;
        if (tx.Vout.First().T != CoinType.System) return VerifyResult.UnableToVerify;
        if (tx.Vout.First().A != 0) return VerifyResult.UnableToVerify;
        if (tx.Vout.First().C.Length != 33) return VerifyResult.UnableToVerify;
        if (!tx.Vout.First().C.Xor(new byte[]
            {
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00
            })) return VerifyResult.UnableToVerify;
        if (tx.Vout.First().E.Length != 33) return VerifyResult.UnableToVerify;
        if (!tx.Vout.First().E.Xor(new byte[]
            {
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00
            })) return VerifyResult.UnableToVerify;
        if (tx.Vout.First().P.Length != 33) return VerifyResult.UnableToVerify;
        if (!tx.Vout.First().P.Xor(new byte[]
            {
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00
            })) return VerifyResult.UnableToVerify;
        const int prefixByteLength = 4;
        var length = BitConverter.ToInt32(tx.Vout.First().N, 0);
        var r = new byte[length];
        tx.Vout.First().N.Skip(prefixByteLength).Take(length).ToArray().CopyTo(r, 0);
        var round = Convert.ToUInt64(r.FromBytes());
        if (round != height) return VerifyResult.UnableToVerify;
        var nSig = tx.Vout.First().N.Skip(prefixByteLength + length).ToArray();
        tx.Vout.First().N = new byte[prefixByteLength + length + nSig.Length];
        var p = round.ToBytes().WrapLengthPrefix();
        Buffer.BlockCopy(p, 0, tx.Vout[0].N, 0, p.Length);
        var valid = _systemCore.Crypto().VerifyXEdDSASignature(nSig, tx.ToHash(), publicKey);
        if (!valid) return VerifyResult.UnableToVerify;
        tx.Vout[0].N = Helper.Util.Combine(p, nSig);
        return tx.TxnId.Xor(tx.ToHash()) ? VerifyResult.Succeed : VerifyResult.UnableToVerify;
    }

    /// <summary>
    /// </summary>
    /// <param name="target"></param>
    /// <param name="script"></param>
    /// <returns></returns>
    public VerifyResult VerifyLockTime(LockTime target, byte[] script)
    {
        Guard.Argument(target, nameof(target)).NotDefault();
        Guard.Argument(script, nameof(script)).NotNull().NotEmpty().MaxCount(16);
        var scr = Encoding.UTF8.GetString(script);
        var sc1 = new Script(Op.GetPushOp(target.Value), OpcodeType.OP_CHECKLOCKTIMEVERIFY);
        var sc2 = new Script(scr);
        if (!sc1.ToBytes().Xor(sc2.ToBytes())) return VerifyResult.UnableToVerify;
        var tx = NBitcoin.Network.Main.CreateTransaction();
        tx.Outputs.Add(new TxOut { ScriptPubKey = new Script(scr) });
        var spending = NBitcoin.Network.Main.CreateTransaction();
        spending.LockTime = new LockTime(DateTimeOffset.UtcNow);
        spending.Inputs.Add(new TxIn(tx.Outputs.AsCoins().First().Outpoint, new Script()));
        spending.Inputs[0].Sequence = 1;
        return spending.Inputs.AsIndexedInputs().First().VerifyScript(tx.Outputs[0])
            ? VerifyResult.Succeed
            : VerifyResult.UnableToVerify;
    }

    /// <summary>
    /// 
    /// </summary>
    /// <returns></returns>
    public async Task<Block> PreviousBlockAdjustedTimeAsync()
    {
        if (await _systemCore.Graph().GetPreviousBlockAsync() is not { } prevBlock) return null;
        return Helper.Util.GetAdjustedTimeAsUnixTimestamp(LedgerConstant.BlockProposalTimeFromSeconds) >
               prevBlock.BlockHeader.Locktime
            ? prevBlock
            : null;
    }

    /// <summary>
    /// </summary>
    /// <param name="transaction"></param>
    /// <returns></returns>
    public async Task<VerifyResult> VerifyKeyImageNotReusedAsync(Transaction transaction)
    {
        Guard.Argument(transaction, nameof(transaction)).NotNull();
        if (transaction.HasErrors().Any()) return VerifyResult.UnableToVerify;
        foreach (var vin in transaction.Vin)
        {
            if (await VerifyKeyImageNotReusedAsync(vin.Image) != VerifyResult.Succeed)
                return VerifyResult.KeyImageAlreadyExists;
        }

        return VerifyResult.Succeed;
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="image"></param>
    /// <returns></returns>
    public async Task<VerifyResult> VerifyKeyImageNotReusedAsync(byte[] image)
    {
        Guard.Argument(image, nameof(image)).NotNull().NotEmpty().MaxCount(33);
        var unitOfWork = _systemCore.UnitOfWork();
        var block = await unitOfWork.HashChainRepository.GetAsync(x =>
            new ValueTask<bool>(x.Txs.Any(c => c.Vin.Any(k => k.Image.Xor(image)))));
        if (block is null) return VerifyResult.Succeed;
        _logger.Fatal("Unable to verify key Image already exists");
        return VerifyResult.KeyImageAlreadyExists;
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="transaction"></param>
    /// <returns></returns>
    public async Task<VerifyResult> VerifyOnetimeKeyNotReusedAsync(Transaction transaction)
    {
        Guard.Argument(transaction, nameof(transaction)).NotNull();
        if (transaction.HasErrors().Any()) return VerifyResult.UnableToVerify;
        foreach (var vout in transaction.Vout)
        {
            if (await VerifyOnetimeKeyNotReusedAsync(vout.P) != VerifyResult.Succeed)
                return VerifyResult.OnetimeKeyAlreadyExists;
        }

        return VerifyResult.Succeed;
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="onetimeKey"></param>
    /// <returns></returns>
    private async Task<VerifyResult> VerifyOnetimeKeyNotReusedAsync(byte[] onetimeKey)
    {
        Guard.Argument(onetimeKey, nameof(onetimeKey)).NotNull().NotEmpty().MaxCount(33);
        var unitOfWork = _systemCore.UnitOfWork();
        var block = await unitOfWork.HashChainRepository.GetAsync(x =>
            new ValueTask<bool>(x.Txs.Any(c => c.Vout.Any(k => k.P.Xor(onetimeKey)))));
        if (block is null) return VerifyResult.Succeed;
        _logger.Fatal("Unable to verify onetime key already exists");
        return VerifyResult.OnetimeKeyAlreadyExists;
    }

    /// <summary>
    /// </summary>
    /// <param name="transaction"></param>
    /// <returns></returns>
    public async Task<VerifyResult> VerifyCommitmentOutputsAsync(Transaction transaction)
    {
        Guard.Argument(transaction, nameof(transaction)).NotNull();
        if (transaction.HasErrors().Any()) return VerifyResult.UnableToVerify;
        var offSets = transaction.Vin.Select(v => v.Offsets).SelectMany(k => k.Split(33)).ToArray();
        var unitOfWork = _systemCore.UnitOfWork();
        foreach (var commit in offSets)
        {
            var blocks = await unitOfWork.HashChainRepository.WhereAsync(x =>
                new ValueTask<bool>(x.Txs.Any(v => v.Vout.Any(c => c.C.Xor(commit)))));
            if (!blocks.Any())
            {
                _logger.Here().Fatal("Unable to find commitment {@Commit}", commit.ByteToHex());
                return VerifyResult.CommitmentNotFound;
            }

            var coinbase = blocks.SelectMany(block => block.Txs).SelectMany(x => x.Vout)
                .FirstOrDefault(output => output.C.Xor(commit) && output.T == CoinType.Coinbase);
            if (coinbase is null) continue;
            var verifyCoinbaseLockTime = VerifyLockTime(new LockTime(Utils.UnixTimeToDateTime(coinbase.L)),
                coinbase.S);
            if (verifyCoinbaseLockTime != VerifyResult.UnableToVerify) continue;
            _logger.Here().Fatal("Unable to verify coinbase commitment lock time {@Commit}", commit.ByteToHex());
            return verifyCoinbaseLockTime;
        }

        return VerifyResult.Succeed;
    }

    /// <summary>
    /// 
    /// </summary>
    /// <returns></returns>
    public async Task<decimal> RunningDistributionAsync()
    {
        try
        {
            var unitOfWork = _systemCore.UnitOfWork();
            var runningDistributionTotal = LedgerConstant.Distribution;
            var height = unitOfWork.HashChainRepository.Count + 1;
            var blockHeaders = await unitOfWork.HashChainRepository.TakeLongAsync(height);
            var orderedBlockHeaders = blockHeaders.OrderBy(x => x.Height).ToArray(blockHeaders.Count);
            var length = height > (ulong)orderedBlockHeaders.Length
                ? orderedBlockHeaders.LongLength
                : orderedBlockHeaders.Length - 1;
            for (var i = 0; i < length; i++)
            {
                if (orderedBlockHeaders[i].BlockPos.StakeType == StakeType.Node)
                    runningDistributionTotal -= NetworkShare(orderedBlockHeaders[i].BlockPos.Solution, height);
            }

            return runningDistributionTotal;
        }
        catch (Exception ex)
        {
            _logger.Here().Error(ex, "Unable to get the running distribution");
        }

        return 0;
    }

    /// <summary>
    /// </summary>
    /// <param name="solution"></param>
    /// <param name="height"></param>
    /// <returns></returns>
    public decimal NetworkShare(ulong solution, ulong height)
    {
        Guard.Argument(solution, nameof(solution)).NotNegative().NotZero();
        const long sub = unchecked((long)LedgerConstant.RewardPercentage * LedgerConstant.Coin);
        return solution * (decimal)sub / LedgerConstant.Coin / LedgerConstant.Distribution;
    }

    /// <summary>
    /// </summary>
    /// <param name="solution"></param>
    /// <param name="previousNetworkShare"></param>
    /// <param name="runningDistributionTotal"></param>
    /// <param name="height"></param>
    /// <returns></returns>
    public VerifyResult VerifyNetworkShare(ulong solution, decimal previousNetworkShare,
        decimal runningDistributionTotal, ulong height)
    {
        Guard.Argument(solution, nameof(solution)).NotNegative().NotZero();
        Guard.Argument(previousNetworkShare, nameof(previousNetworkShare)).NotNegative().NotZero();
        Guard.Argument(runningDistributionTotal, nameof(runningDistributionTotal)).NotNegative().NotZero();
        var previousRunningDistribution = runningDistributionTotal + previousNetworkShare;
        if (previousRunningDistribution > LedgerConstant.Distribution) return VerifyResult.UnableToVerify;
        var networkShare = NetworkShare(solution, height).ConvertToUInt64().DivCoin();
        previousNetworkShare = previousNetworkShare.ConvertToUInt64().DivCoin();
        return networkShare == previousNetworkShare ? VerifyResult.Succeed : VerifyResult.UnableToVerify;
    }

    /// <summary>
    /// </summary>
    /// <param name="solution"></param>
    /// <param name="networkShare"></param>
    /// <returns></returns>
    public uint Bits(ulong solution, decimal networkShare)
    {
        Guard.Argument(solution, nameof(solution)).NotZero();
        Guard.Argument(networkShare, nameof(networkShare)).NotNegative().NotZero();
        var diff = Math.Truncate(solution * networkShare / LedgerConstant.Bits);
        diff = diff == 0 ? 1 : diff;
        return (uint)diff;
    }

    /// <summary>
    /// </summary>
    /// <param name="sig"></param>
    /// <param name="kernel"></param>
    /// <returns></returns>
    public VerifyResult VerifyKernel(byte[] sig, byte[] kernel)
    {
        Guard.Argument(sig, nameof(sig)).NotNull().MaxCount(96);
        Guard.Argument(kernel, nameof(kernel)).NotNull().MaxCount(32);
        var v = new BigInteger(Hasher.Hash(sig).HexToByte());
        var T = new BigInteger(kernel);
        return v.CompareTo(T) <= 0 ? VerifyResult.Succeed : VerifyResult.UnableToVerify;
    }

    /// <summary>
    /// </summary>
    /// <param name="solution"></param>
    /// <param name="height"></param>
    /// <returns></returns>
    public async Task<decimal> CurrentRunningDistributionAsync(ulong solution, ulong height)
    {
        Guard.Argument(solution, nameof(solution)).NotNegative().NotZero();
        var runningDistribution = await RunningDistributionAsync();
        height++;
        if (runningDistribution == LedgerConstant.Distribution)
            runningDistribution -= NetworkShare(solution, height);
        var networkShare = NetworkShare(solution, height);
        runningDistribution -= networkShare.ConvertToUInt64().DivCoin();
        return runningDistribution;
    }

    /// <summary>
    /// </summary>
    /// <param name="prevHash"></param>
    /// <param name="hash"></param>
    /// <param name="round"></param>
    /// <returns></returns>
    public byte[] NetworkKernel(byte[] prevHash, byte[] hash, ulong round)
    {
        Guard.Argument(prevHash, nameof(prevHash)).NotNull().MaxCount(32);
        Guard.Argument(hash, nameof(hash)).NotNull().MaxCount(32);
        try
        {
            var txHashBig = new BigInteger(1, hash).Multiply(
                new BigInteger(Hasher.Hash(prevHash).HexToByte()).Multiply(
                    new BigInteger(Hasher.Hash(round.ToBytes()).HexToByte())));
            var kernel = Hasher.Hash(txHashBig.ToByteArray()).HexToByte();
            return kernel;
        }
        catch (Exception ex)
        {
            _logger.Here().Fatal(ex, "Error while creating the kernel");
        }

        return null;
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="vrfOutput"></param>
    /// <param name="round"></param>
    /// <returns></returns>
    public async Task<byte[]> NodeKernelAsync(byte[] vrfOutput, ulong round)
    {
        Guard.Argument(vrfOutput, nameof(vrfOutput)).NotNull().MaxCount(32);
        try
        {
            var prevBlock = await _systemCore.Graph().GetPreviousBlockAsync();
            if (prevBlock != null)
            {
                return Helper.Util.Combine(vrfOutput, prevBlock.Hash,
                    Hasher.Hash(round.ToBytes()).HexToByte());
            }
        }
        catch (Exception ex)
        {
            _logger.Here().Fatal(ex, "Error while creating the node kernel");
        }

        return null;
    }

    /// <summary>
    /// </summary>
    /// <param name="otherChain"></param>
    /// <returns></returns>
    public async Task<Block[]> ForkRuleAsync(Block[] otherChain)
    {
        Guard.Argument(otherChain, nameof(otherChain)).NotNull().NotEmpty();
        try
        {
            var unitOfWork = _systemCore.UnitOfWork();
            var mainChain = (await unitOfWork.HashChainRepository.WhereAsync(x =>
                new ValueTask<bool>(x.Height >= otherChain.Min(o => o.Height)))).OrderBy(x => x.Height).ToArray();
            var newChain = otherChain.OrderBy(x => x.Height).Take(mainChain.Length).ToArray();
            var mainChainTime = mainChain.Sum(main => Helper.Util.UnixTimeToDateTime(main.BlockHeader.Locktime).Ticks);
            var newChainTime = newChain.Sum(other => Helper.Util.UnixTimeToDateTime(other.BlockHeader.Locktime).Ticks);
            if (mainChainTime >= newChainTime)
            {
                if (mainChain.Length != newChain.Length) return Array.Empty<Block>();
            }

            foreach (var block in mainChain) unitOfWork.HashChainRepository.Delete(block.Hash, block.BlockHeader.PrevBlockHash);
            return otherChain;
        }
        catch (Exception ex)
        {
            _logger.Here().Fatal(ex, "Error while processing fork rule");
        }

        return null;
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="blocks"></param>
    /// <returns></returns>
    public VerifyResult VerifyBlocksWithNoDuplicateHeights(IReadOnlyList<Block> blocks)
    {
        Guard.Argument(blocks, nameof(blocks)).NotNull().NotEmpty();
        var noDupHeights = new List<ulong>();
        foreach (var block in blocks)
        {
            var height = noDupHeights.FirstOrDefault(x => x == block.Height);
            if (height != 0) return VerifyResult.AlreadyExists;
            noDupHeights.Add(block.Height);
        }

        return VerifyResult.Succeed;
    }

    /// <summary>
    /// </summary>
    /// <param name="m"></param>
    /// <param name="outputs"></param>
    /// <param name="keyOffset"></param>
    /// <param name="cols"></param>
    /// <param name="rows"></param>
    /// <returns></returns>
    private byte[] GenerateMlSag(byte[] m, Vout[] outputs, byte[] keyOffset, int cols, int rows)
    {
        Guard.Argument(m, nameof(m)).NotNull().NotEmpty();
        Guard.Argument(outputs, nameof(outputs)).NotNull().NotEmpty();
        Guard.Argument(keyOffset, nameof(keyOffset)).NotNull().NotEmpty();
        Guard.Argument(cols, nameof(cols)).NotNegative().NotZero();
        Guard.Argument(rows, nameof(rows)).NotNegative().NotZero();
        var index = 0;
        var vOutputs = outputs.Select(x => x.T.ToString()).ToArray();
        if (vOutputs.Contains(CoinType.Coinbase.ToString()) &&
            vOutputs.Contains(CoinType.Coinstake.ToString())) index++;
        var pcmOut = new Span<byte[]>(new[] { outputs[index].C, outputs[index + 1].C });
        var pcmIn = keyOffset.Split(33).Select(x => x).ToArray();
        using var mlsag = new MLSAG();
        if (mlsag.Prepare(m, null, pcmOut.Length, pcmOut.Length, cols, rows, pcmIn, pcmOut, null)) return m;
        _logger.Fatal("Unable to verify MLSAG");
        return null;
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="prevMerkelRoot"></param>
    /// <param name="txStream"></param>
    /// <param name="index"></param>
    /// <param name="transactions"></param>
    /// <returns></returns>
    /// <exception cref="ArithmeticException"></exception>
    public byte[] MembershipProof(byte[] prevMerkelRoot, byte[] txStream, int index, Transaction[] transactions)
    {
        Guard.Argument(prevMerkelRoot, nameof(prevMerkelRoot)).NotNull().MaxCount(32);
        Guard.Argument(txStream, nameof(txStream)).NotNull().NotEmpty();
        var hasher = Hasher.New();
        hasher.Update(prevMerkelRoot);
        foreach (var (transaction, i) in transactions.WithIndex())
        {
            var hasAnyErrors = transaction.HasErrors();
            if (hasAnyErrors.Any()) throw new ArithmeticException("Unable to validate the transaction");
            hasher.Update(index == i ? txStream : transaction.ToStream());
        }

        var hash = hasher.Finalize();
        return hash.HexToByte();
    }
}