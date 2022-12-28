// Tangram by Matthew Hellyer is licensed under CC BY-NC-ND 4.0.
// To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics;
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

namespace TangramXtgm.Ledger;

/// <summary>
/// </summary>
public interface IValidator
{
    VerifyResult VerifyBlockGraphSignatureNodeRound(BlockGraph blockGraph);
    VerifyResult VerifyBulletProof(Vout[] vOutputs, Bp[] bulletProofs);
    VerifyResult VerifyCoinbaseTransaction(Vout coinbase, ulong solution, decimal runningDistribution, ulong height);
    VerifyResult VerifySolution(byte[] vrfBytes, byte[] kernel, ulong solution);
    Task<VerifyResult> VerifyBlockAsync(Block block);
    Task<VerifyResult> VerifyBlocksAsync(Block[] blocks);
    Task<VerifyResult> VerifyTransactionAsync(Transaction transaction);
    Task<VerifyResult> VerifyTransactionsAsync(IList<Transaction> transactions);
    VerifyResult VerifySloth(uint t, byte[] message, byte[] nonce);
    uint Bits(ulong solution, decimal networkShare);
    decimal NetworkShare(ulong solution, ulong height);
    Task<ulong> SolutionAsync(byte[] vrfBytes, byte[] kernel);
    VerifyResult VerifyKernel(byte[] calculateVrfSig, byte[] kernel);
    VerifyResult VerifyLockTime(LockTime target, byte[] script);
    VerifyResult VerifyCommit(Vout[] vOutputs);
    Task<VerifyResult> VerifyKeyImageNotExistsAsync(Transaction transaction);
    Task<VerifyResult> VerifyKeyImageNotExistsAsync(byte[] image);
    Task<VerifyResult> VerifyCommitmentOutputsAsync(Transaction transaction);
    Task<decimal> GetCurrentRunningDistributionAsync(ulong solution, ulong height);
    Task<decimal> GetRunningDistributionAsync();
    VerifyResult VerifyNetworkShare(ulong solution, decimal previousNetworkShare, decimal runningDistributionTotal, ulong height);
    Task<VerifyResult> VerifyBlockHashAsync(Block block);
    Task<VerifyResult> VerifyVrfProofAsync(byte[] publicKey, byte[] vrfProof, byte[] kernel);
    Task<VerifyResult> VerifyMerkleAsync(Block block);
    VerifyResult VerifyTransactionTime(in Transaction transaction);
    byte[] Kernel(byte[] prevHash, byte[] hash, ulong round);
    Task<Block[]> VerifyForkRuleAsync(Block[] xChain);
    VerifyResult VerifyMlsag(Transaction transaction);
    VerifyResult VerifyNoDuplicateImageKeys(IList<Transaction> transactions);
    VerifyResult VerifyNoDuplicateBlockHeights(IReadOnlyList<Block> blocks);
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
        var blockResponse = await GetBlockAsync(block.Height);
        if (blockResponse.Block is null) return VerifyResult.UnableToVerify;
        using var hasher = Hasher.New();
        hasher.Update(blockResponse.Block.Hash);
        hasher.Update(block.ToHash());
        var hash = hasher.Finalize();
        var verifyHasher = hash.HexToByte().Xor(block.Hash);
        return verifyHasher ? VerifyResult.Succeed : VerifyResult.UnableToVerify;
    }

    /// <summary>
    /// </summary>
    /// <param name="block"></param>
    /// <returns></returns>
    public async Task<VerifyResult> VerifyMerkleAsync(Block block)
    {
        Guard.Argument(block, nameof(block)).NotNull();
        var blockResponse = await GetBlockAsync(block.Height);
        if (blockResponse.Block is null) return VerifyResult.UnableToVerify;
        var merkelRoot =
            BlockHeader.ToMerkleRoot(blockResponse.Block.BlockHeader.MerkleRoot, block.Txs.ToImmutableArray());
        var verifyMerkel = merkelRoot.Xor(block.BlockHeader.MerkleRoot);
        return verifyMerkel ? VerifyResult.Succeed : VerifyResult.UnableToVerify;
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="height"></param>
    /// <returns></returns>
    private async Task<BlockResponse> GetBlockAsync(ulong height)
    {
        var blockResponse = await _systemCore.Graph().GetBlockByHeightAsync(new BlockByHeightRequest(height));
        if (blockResponse.Block is not null) return blockResponse;
        _logger.Here().Error("No block available");
        return new BlockResponse(null);
    }

    /// <summary>
    /// </summary>
    /// <param name="blockGraph"></param>
    /// <returns></returns>
    public VerifyResult VerifyBlockGraphSignatureNodeRound(BlockGraph blockGraph)
    {
        Guard.Argument(blockGraph, nameof(blockGraph)).NotNull();
        try
        {
            if (!_systemCore.Crypto()
                    .VerifySignature(blockGraph.PublicKey, blockGraph.ToHash(), blockGraph.Signature))
            {
                _logger.Error("Unable to verify the signature for block {@Round} from node {@Node}",
                    blockGraph.Block.Round, blockGraph.Block.Node);
                return VerifyResult.UnableToVerify;
            }

            if (blockGraph.Prev == null) return VerifyResult.UnableToVerify;
            if (blockGraph.Prev.Round != 0)
            {
                if (blockGraph.Prev.Node != blockGraph.Block.Node)
                {
                    _logger.Error("Previous block node does not match block {@Round} from node {@Node}",
                        blockGraph.Block.Round, blockGraph.Block.Node);
                    return VerifyResult.UnableToVerify;
                }

                if (blockGraph.Prev.Round + 1 != blockGraph.Block.Round)
                {
                    _logger.Error("Previous block round is invalid on block {@Round} from node {@Node}",
                        blockGraph.Block.Round, blockGraph.Block.Node);
                    return VerifyResult.UnableToVerify;
                }
            }

            if (blockGraph.Dependencies.Any(dep => dep.Block.Node == blockGraph.Block.Node))
            {
                _logger.Error(
                    "Block references includes a block from the same node in block {@Round} from node {@Node}",
                    blockGraph.Block.Round, blockGraph.Block.Node);
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
            var commitments = vOutputs.Where(x => x.T == CoinType.Change).ToArray();
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

                var payment = vOutputs[index].C;
                index++;
                var change = vOutputs[index].C;
                var commitSumBalance = pedersen.CommitSum(new List<byte[]> { payment, change }, new List<byte[]>());
                if (pedersen.VerifyCommitSum(new List<byte[]> { commitSumBalance },
                        new List<byte[]> { payment, change }))
                {
                    index++;
                    vCount -= index;
                    if (vCount <= 0) break;
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
    /// </summary>
    /// <param name="vrfBytes"></param>
    /// <param name="kernel"></param>
    /// <param name="solution"></param>
    /// <returns></returns>
    public VerifyResult VerifySolution(byte[] vrfBytes, byte[] kernel, ulong solution)
    {
        Guard.Argument(vrfBytes, nameof(vrfBytes)).NotNull().MaxCount(96);
        Guard.Argument(kernel, nameof(kernel)).NotNull().MaxCount(32);
        Guard.Argument(solution, nameof(solution)).NotNegative().NotZero();
        var isSolution = false;
        try
        {
            if (LedgerConstant.SolutionThrottle > solution)
            {
                var target = new BigInteger(1, Hasher.Hash(vrfBytes).HexToByte());
                var weight = BigInteger.ValueOf(Convert.ToInt64(solution));
                var hashTarget = new BigInteger(1, kernel);
                var weightedTarget = target.Multiply(weight);
                isSolution = hashTarget.CompareTo(weightedTarget) <= 0;
            }
        }
        catch (Exception ex)
        {
            _logger.Here().Error(ex, "Unable to verify the solution");
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
        if (VerifySloth(block.BlockPos.Bits, block.BlockPos.VrfSig, block.BlockPos.Nonce) != VerifyResult.Succeed)
        {
            _logger.Here().Fatal("Unable to verify the slow function");
            return VerifyResult.UnableToVerify;
        }

        var runningDistribution = await GetCurrentRunningDistributionAsync(block.BlockPos.Solution, block.Height);
        if (VerifyCoinbaseTransaction(block.Txs.First().Vout.First(), block.BlockPos.Solution, runningDistribution,
                block.Height) != VerifyResult.Succeed)
        {
            _logger.Fatal("Unable to verify the coinbase transaction");
            return VerifyResult.UnableToVerify;
        }

        var hashTransactions =
            _systemCore.Graph().HashTransactions(
                new HashTransactionsRequest(block.Txs.Skip(1).ToArray(block.Txs.Count - 1)));
        if (hashTransactions == null)
        {
            _logger.Fatal("Unable to verify hashed transactions");
            return VerifyResult.UnableToVerify;
        }

        var kernel = Kernel(block.BlockHeader.PrevBlockHash, hashTransactions, block.Height);
        if (VerifyKernel(block.BlockPos.VrfProof, kernel) != VerifyResult.Succeed)
        {
            _logger.Fatal("Unable to verify kernel");
            return VerifyResult.UnableToVerify;
        }

        if (await VerifyVrfProofAsync(block.BlockPos.PublicKey, block.BlockPos.VrfProof, kernel) != VerifyResult.Succeed)
        {
            _logger.Fatal("Unable to verify the Vrf Proof");
            return VerifyResult.UnableToVerify;
        }

        if (VerifySolution(block.BlockPos.VrfProof, kernel, block.BlockPos.Solution) != VerifyResult.Succeed)
        {
            _logger.Fatal("Unable to verify the solution");
            return VerifyResult.UnableToVerify;
        }

        var bits = Bits(block.BlockPos.Solution, block.Txs.First().Vout.First().A.DivCoin());
        if (block.BlockPos.Bits != bits)
        {
            _logger.Fatal("Unable to verify the bits");
            return VerifyResult.UnableToVerify;
        }

        if (VerifyLockTime(new LockTime(Utils.UnixTimeToDateTime(block.BlockHeader.Locktime)),
                block.BlockHeader.LocktimeScript) != VerifyResult.Succeed)
        {
            _logger.Fatal("Unable to verify the block lock time");
            return VerifyResult.UnableToVerify;
        }

        if (block.BlockHeader.MerkleRoot.Xor(LedgerConstant.BlockZeroMerkel) &&
            block.BlockHeader.PrevBlockHash.Xor(LedgerConstant.BlockZeroPrevHash)) return VerifyResult.Succeed;
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

        if (VerifyNoDuplicateImageKeys(block.Txs) != VerifyResult.Succeed)
        {
            _logger.Fatal("Unable to verify transactions found duplicate image keys");
            return VerifyResult.UnableToVerify;
        }

        if (await VerifyTransactionsAsync(block.Txs) == VerifyResult.Succeed) return VerifyResult.Succeed;
        _logger.Fatal("Unable to verify the block transactions");
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
        if (outputs.Contains(Enum.GetName(CoinType.Payment)) && outputs.Contains(Enum.GetName(CoinType.Change)))
        {
            if (VerifyTransactionTime(in transaction) != VerifyResult.Succeed)
                return VerifyResult.UnableToVerify;
        }

        if (await VerifyCommitmentOutputsAsync(transaction) != VerifyResult.Succeed) return VerifyResult.UnableToVerify;
        if (await VerifyKeyImageNotExistsAsync(transaction) != VerifyResult.Succeed)
            return VerifyResult.KeyImageAlreadyExists;
        if (VerifyCommit(transaction.Vout) != VerifyResult.Succeed) return VerifyResult.UnableToVerify;
        if (VerifyBulletProof(transaction.Vout, transaction.Bp) != VerifyResult.Succeed) return VerifyResult.UnableToVerify;
        return VerifyMlsag(transaction);
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="transactions"></param>
    public VerifyResult VerifyNoDuplicateImageKeys(IList<Transaction> transactions)
    {
        var noDupImageKeys = new List<byte[]>();
        foreach (var transaction in transactions)
            foreach (var vin in transaction.Vin)
            {
                var vInput = noDupImageKeys.FirstOrDefault(x => x.Xor(vin.Image));
                if (vInput is not null) return VerifyResult.AlreadyExists;
                noDupImageKeys.Add(vin.Image);
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
        using var mlsag = new MLSAG();
        var skip = 0;
        for (var i = 0; i < transaction.Vin.Length; i++)
        {
            var take = transaction.Vout[skip].T == CoinType.Coinbase ? 3 : 2;
            var m = GenerateMlsag(transaction.Rct[i].M, transaction.Vout.Skip(skip).Take(take).ToArray(),
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
    public VerifyResult VerifyTransactionTime(in Transaction transaction)
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

            var t = TimeSpan.FromTicks(transaction.Vtime.W).TotalSeconds;
            if (t < LedgerConstant.TransactionDefaultTimeDelayFromSeconds) return VerifyResult.UnableToVerify;
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
    /// <param name="runningDistribution"></param>
    /// <param name="height"></param>
    /// <returns></returns>
    public VerifyResult VerifyCoinbaseTransaction(Vout coinbase, ulong solution, decimal runningDistribution, ulong height)
    {
        Guard.Argument(coinbase, nameof(coinbase)).NotNull();
        Guard.Argument(solution, nameof(solution)).NotNegative().NotZero();
        Guard.Argument(runningDistribution, nameof(runningDistribution)).NotNegative().NotZero();
        if (coinbase.Validate().Any()) return VerifyResult.UnableToVerify;
        if (coinbase.T != CoinType.Coinbase) return VerifyResult.UnableToVerify;
        if (VerifyNetworkShare(solution, coinbase.A.DivCoin(), runningDistribution, height) != VerifyResult.Succeed)
            return VerifyResult.UnableToVerify;
        using var pedersen = new Pedersen();
        var commit = pedersen.Commit(coinbase.A, coinbase.D);
        return commit.Xor(coinbase.C) ? VerifyResult.Succeed : VerifyResult.UnableToVerify;
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
    /// </summary>
    /// <param name="transaction"></param>
    /// <returns></returns>
    public async Task<VerifyResult> VerifyKeyImageNotExistsAsync(Transaction transaction)
    {
        Guard.Argument(transaction, nameof(transaction)).NotNull();
        if (transaction.HasErrors().Any()) return VerifyResult.UnableToVerify;
        var unitOfWork = _systemCore.UnitOfWork();
        foreach (var vin in transaction.Vin)
        {
            var block = await unitOfWork.HashChainRepository.GetAsync(x =>
                new ValueTask<bool>(x.Txs.Any(c => c.Vin.Any(k => k.Image.Xor(vin.Image)))));
            if (block is null) continue;
            _logger.Fatal("Unable to verify key Image already exists");
            return VerifyResult.KeyImageAlreadyExists;
        }

        return VerifyResult.Succeed;
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="image"></param>
    /// <returns></returns>
    public async Task<VerifyResult> VerifyKeyImageNotExistsAsync(byte[] image)
    {
        Guard.Argument(image, nameof(image)).NotNull();
        var unitOfWork = _systemCore.UnitOfWork();
        var block = await unitOfWork.HashChainRepository.GetAsync(x =>
            new ValueTask<bool>(x.Txs.Any(c => c.Vin.Any(k => k.Image.Xor(image)))));
        if (block is null) return VerifyResult.Succeed;
        _logger.Fatal("Unable to verify key Image already exists");
        return VerifyResult.KeyImageAlreadyExists;
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
    /// </summary>
    /// <param name="publicKey"></param>
    /// <param name="vrfProof"></param>
    /// <param name="kernel"></param>
    /// <returns></returns>
    public async Task<VerifyResult> VerifyVrfProofAsync(byte[] publicKey, byte[] vrfProof, byte[] kernel)
    {
        Guard.Argument(publicKey, nameof(publicKey)).NotNull().MaxCount(33);
        Guard.Argument(vrfProof, nameof(vrfProof)).NotNull().MaxCount(96);
        Guard.Argument(kernel, nameof(kernel)).NotNull().MaxCount(32);
        try
        {
            _systemCore.Crypto()
               .GetVerifyVrfSignature(Curve.decodePoint(publicKey, 0), kernel, vrfProof);
            return VerifyResult.Succeed;
        }
        catch (Exception ex)
        {
            _logger.Here().Fatal(ex, "Unable to verify Vrf signature");
        }

        return VerifyResult.UnableToVerify;
    }

    /// <summary>
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
            var sloth = new Sloth(0, ct);
            var x = System.Numerics.BigInteger.Parse(message.ByteToHex(), NumberStyles.AllowHexSpecifier);
            var y = System.Numerics.BigInteger.Parse(nonce.FromBytes());
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
    /// <returns></returns>
    public async Task<decimal> GetRunningDistributionAsync()
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
        Guard.Argument(height, nameof(height)).NotNegative();
        var halving = (int)(height / LedgerConstant.BlockHalving);
        if (halving >= 64) return 0;
        var sub = unchecked((long)LedgerConstant.RewardPercentage * LedgerConstant.Coin);
        sub >>= halving;
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
        Guard.Argument(solution, nameof(solution)).NotNegative().NotZero();
        Guard.Argument(networkShare, nameof(networkShare)).NotNegative();
        var diff = Math.Truncate(solution * networkShare / LedgerConstant.Bits);
        diff = diff == 0 ? 1 : diff;
        return (uint)diff;
    }

    /// <summary>
    /// </summary>
    /// <returns></returns>
    public async Task<ulong> SolutionAsync(byte[] vrfBytes, byte[] kernel)
    {
        Guard.Argument(vrfBytes, nameof(vrfBytes)).NotNull().MaxCount(96);
        Guard.Argument(kernel, nameof(kernel)).NotNull().MaxCount(32);
        return await Task.Factory.StartNew(() =>
        {
            var sw = new Stopwatch();
            try
            {
                long itr = 0;
                var target = new BigInteger(1, Hasher.Hash(vrfBytes).HexToByte());
                var hashTarget = new BigInteger(1, kernel);
                var hashTargetValue = new BigInteger((target.IntValue / hashTarget.BitCount).ToString()).Abs();
                var hashWeightedTarget = new BigInteger(1, kernel).Multiply(hashTargetValue);
                sw.Start();
                while (!_systemCore.ApplicationLifetime.ApplicationStopping.IsCancellationRequested)
                {
                    if (sw.ElapsedMilliseconds > LedgerConstant.SolutionCancellationTimeoutFromMilliseconds)
                    {
                        _logger.Information("Solution time: ({@T})  iterations: ({@R})  [FAILED]",
                            sw.Elapsed.TotalSeconds, itr);
                        itr = 0;
                        break;
                    }

                    var weightedTarget = target.Multiply(BigInteger.ValueOf(itr));
                    if (hashWeightedTarget.CompareTo(weightedTarget) <= 0)
                    {
                        _logger.Information("Solution time: ({@T})  iterations: ({@R})  [PASSED]",
                            sw.Elapsed.TotalSeconds, itr);
                        break;
                    }

                    if (itr == long.MaxValue)
                    {
                        itr = 0;
                        break;
                    }

                    itr++;
                }

                return (ulong)itr;
            }
            catch (Exception ex)
            {
                _logger.Here().Error("{@Message}", ex.Message);
            }
            finally
            {
                sw.Stop();
            }

            return 0ul;
        }, TaskCreationOptions.LongRunning).ConfigureAwait(false);
    }

    /// <summary>
    /// </summary>
    /// <param name="calculateVrfSig"></param>
    /// <param name="kernel"></param>
    /// <returns></returns>
    public VerifyResult VerifyKernel(byte[] calculateVrfSig, byte[] kernel)
    {
        Guard.Argument(calculateVrfSig, nameof(calculateVrfSig)).NotNull().MaxCount(96);
        Guard.Argument(kernel, nameof(kernel)).NotNull().MaxCount(32);
        var v = new BigInteger(Hasher.Hash(calculateVrfSig).HexToByte());
        var T = new BigInteger(kernel);
        return v.CompareTo(T) <= 0 ? VerifyResult.Succeed : VerifyResult.UnableToVerify;
    }

    /// <summary>
    /// </summary>
    /// <param name="solution"></param>
    /// <param name="height"></param>
    /// <returns></returns>
    public async Task<decimal> GetCurrentRunningDistributionAsync(ulong solution, ulong height)
    {
        Guard.Argument(solution, nameof(solution)).NotNegative().NotZero();
        var runningDistribution = await GetRunningDistributionAsync();
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
    public byte[] Kernel(byte[] prevHash, byte[] hash, ulong round)
    {
        Guard.Argument(prevHash, nameof(prevHash)).NotNull().MaxCount(32);
        Guard.Argument(hash, nameof(hash)).NotNull().MaxCount(32);
        var txHashBig = new BigInteger(1, hash).Multiply(
            new BigInteger(Hasher.Hash(prevHash).HexToByte()).Multiply(
                new BigInteger(Hasher.Hash(round.ToBytes()).HexToByte())));
        var kernel = Hasher.Hash(txHashBig.ToByteArray()).HexToByte();
        return kernel;
    }

    /// <summary>
    /// </summary>
    /// <param name="otherChain"></param>
    /// <returns></returns>
    public async Task<Block[]> VerifyForkRuleAsync(Block[] otherChain)
    {
        Guard.Argument(otherChain, nameof(otherChain)).NotNull().NotEmpty();
        try
        {
            var unitOfWork = _systemCore.UnitOfWork();
            var mainChain = (await unitOfWork.HashChainRepository.WhereAsync(x =>
                new ValueTask<bool>(x.Height >= otherChain.Min(o => o.Height)))).OrderBy(x => x.Height).ToArray();
            var newChain = otherChain.OrderBy(x => x.Height).Take(mainChain.Length).ToArray();
            var mainChainBits = mainChain.Aggregate(0UL, (ul, b) => ul + b.BlockPos.Bits);
            var newChainBits = newChain.Aggregate(0UL, (ul, b) => ul + b.BlockPos.Bits);
            if (mainChainBits >= newChainBits)
            {

                if (mainChain.Length != newChain.Length) return Array.Empty<Block>();
            }

            foreach (var block in mainChain) unitOfWork.HashChainRepository.Delete(block.Hash);
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
    public VerifyResult VerifyNoDuplicateBlockHeights(IReadOnlyList<Block> blocks)
    {
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
    private byte[] GenerateMlsag(byte[] m, Vout[] outputs, byte[] keyOffset, int cols, int rows)
    {
        Guard.Argument(m, nameof(m)).NotNull();
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
}