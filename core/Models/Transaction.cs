// Tangram by Matthew Hellyer is licensed under CC BY-NC-ND 4.0.
// To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0

using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using Blake3;
using TangramXtgm.Cryptography;
using TangramXtgm.Extensions;
using TangramXtgm.Helper;
using TangramXtgm.Ledger;

namespace TangramXtgm.Models;

[MessagePack.MessagePackObject]
public record Transaction : IComparable<Transaction>
{
    /// <summary>
    /// </summary>
    /// <param name="other"></param>
    /// <returns></returns>
    public int CompareTo(Transaction other)
    {
        if (ReferenceEquals(this, other)) return 0;
        if (ReferenceEquals(null, other)) return 1;
        var txIdComparison = string.Compare(TxnId.ByteToHex(), other.TxnId.ByteToHex(), StringComparison.Ordinal);
        return txIdComparison != 0
            ? txIdComparison
            : string.Compare(TxnId.ByteToHex(), other.TxnId.ByteToHex(), StringComparison.Ordinal);
    }

    [MessagePack.Key(0)] public byte[] TxnId { get; set; }
    [MessagePack.Key(1)] public Bp[] Bp { get; set; }
    [MessagePack.Key(2)] public int Ver { get; set; } = 3;
    [MessagePack.Key(3)] public int Mix { get; set; } = 22;
    [MessagePack.Key(4)] public Vin[] Vin { get; set; }
    [MessagePack.Key(5)] public Vout[] Vout { get; set; }
    [MessagePack.Key(6)] public Rct[] Rct { get; set; }
    [MessagePack.Key(7)] public Vtime Vtime { get; set; }

    /// <summary>
    /// </summary>
    /// <returns></returns>
    public IEnumerable<ValidationResult> HasErrors()
    {
        var results = new List<ValidationResult>();
        if (TxnId == null) results.Add(new ValidationResult("Argument is null", new[] { "TxnId" }));
        if (TxnId != null && TxnId.Length != 32)
            results.Add(new ValidationResult("Range exception", new[] { "TxnId" }));
        if (!TxnId.Xor(ToHash())) results.Add(new ValidationResult("Range exception", new[] { "TxnId" }));
        if (Mix < 0) results.Add(new ValidationResult("Range exception", new[] { "Mix" }));
        if (Mix != 22) results.Add(new ValidationResult("Range exception", new[] { "Mix" }));
        if (Rct == null) results.Add(new ValidationResult("Argument is null", new[] { "Rct" }));
        if (!((Ver >= ushort.MinValue) & (Ver <= ushort.MaxValue)))
            results.Add(new ValidationResult("Incorrect number", new[] { "Ver" }));
        if (Vin == null) results.Add(new ValidationResult("Argument is null", new[] { "Vin" }));
        if (Vout == null) results.Add(new ValidationResult("Argument is null", new[] { "Vout" }));
        if (Bp != null)
        {
            foreach (var bp in Bp) results.AddRange(bp.Validate());
            results = HasDuplicateBulletProofs(results, Bp).ToList();
        }

        if (Vin != null)
        {
            foreach (var vi in Vin) results.AddRange(vi.Validate());
            results = HasDuplicateInputs(results, Vin).ToList();
        }

        if (Vout != null)
        {
            foreach (var vo in Vout) results.AddRange(vo.Validate());
            results = HasDuplicateOutputs(results, Vout).ToList();
        }

        if (Rct != null)
        {
            foreach (var rct in Rct) results.AddRange(rct.Validate());
            results = HasDuplicateRing(results, Rct).ToList();
        }

        var outputType = OutputType();
        if (outputType != CoinType.Payment && outputType != CoinType.Burn && outputType != CoinType.Mint) return results;
        if (Vtime == null) results.Add(new ValidationResult("Argument is null", new[] { "Vtime" }));
        if (Vtime != null)
        {
            results.AddRange(Vtime.Validate());
            if (Ver < 3) return results;
            if (Vtime.T < 5) results.Add(new ValidationResult("Range exception", new[] { "T" }));
            if (Vtime.K < 0) results.Add(new ValidationResult("Range exception", new[] { "K" }));
        }

        return results;
    }

    /// <summary>
    /// </summary>
    /// <returns></returns>
    public byte[] ToHash()
    {
        return Hasher.Hash(ToStream()).HexToByte();
    }

    /// <summary>
    /// </summary>
    /// <returns></returns>
    public byte[] ToStream()
    {
        using var ts = new BufferStream();
        ts.Append(Mix).Append(Ver);
        foreach (var bp in Bp) ts.Append(bp.Proof);
        foreach (var vin in Vin)
        {
            ts.Append(vin.Image);
            ts.Append(vin.Offsets);
        }

        foreach (var vout in Vout)
        {
            ts.Append(vout.A).Append(vout.C).Append(vout.E).Append(vout.L).Append(vout.N).Append(vout.P)
                .Append(vout.S ?? Array.Empty<byte>()).Append(Enum.GetName(vout.T))
                .Append(vout.D ?? Array.Empty<byte>());
        }

        foreach (var rct in Rct) ts.Append(rct.I).Append(rct.M).Append(rct.P).Append(rct.S);
        if (Vtime == null) return ts.ToArray();
        ts.Append(Vtime.I).Append(Vtime.L).Append(Vtime.M).Append(Vtime.N).Append(Vtime.S).Append(Vtime.W);
        if (Ver == 3) ts.Append(Vtime.T).Append(Vtime.K);
        return ts.ToArray();
    }

    /// <summary>
    /// </summary>
    /// <returns></returns>
    public CoinType OutputType()
    {
        var coinType = CoinType.System;
        var outputs = Vout.Select(x => Enum.GetName(x.T)).ToArray();
        if (outputs.Contains(Enum.GetName(CoinType.Payment)) && outputs.Contains(Enum.GetName(CoinType.Change)))
            coinType = CoinType.Payment;
        if (outputs.Contains(Enum.GetName(CoinType.Burn)) && outputs.Contains(Enum.GetName(CoinType.Mint)))
            coinType = CoinType.Mint;
        if (outputs.Contains(Enum.GetName(CoinType.Coinbase)) && outputs.Contains(Enum.GetName(CoinType.Coinstake)))
            coinType = CoinType.Coinstake;
        return coinType;
    }

    /// <summary>
    /// </summary>
    /// <returns></returns>
    public ushort GetSize()
    {
        return (ushort)ToStream().Length;
    }

    /// <summary>
    /// </summary>
    /// <returns></returns>
    public override int GetHashCode()
    {
        return HashCode.Combine(TxnId.ByteToHex());
    }
    
    /// <summary>
    /// 
    /// </summary>
    /// <param name="validationResults"></param>
    /// <param name="bulletProofs"></param>
    /// <returns></returns>
    private IEnumerable<ValidationResult> HasDuplicateBulletProofs(List<ValidationResult> validationResults, Bp[] bulletProofs)
    {
        var duplicateBulletProof = new List<byte[]>();
        foreach (var bulletProof in bulletProofs)
        {
            if (duplicateBulletProof.FirstOrDefault(x => x.Xor(bulletProof.Proof)) is not null)
            {
                validationResults.Add(new ValidationResult("Duplicate bullet proof exists", new[] { "bp" }));
                return validationResults;
            }
            duplicateBulletProof.Add(bulletProof.Proof);
        }

        return validationResults;
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="validationResults"></param>
    /// <param name="vInputs"></param>
    /// <returns></returns>
    private IEnumerable<ValidationResult> HasDuplicateInputs(List<ValidationResult> validationResults, Vin[] vInputs)
    {
        var duplicateInputs = new List<byte[]>();
        foreach (var vin in vInputs)
        {
            if (duplicateInputs.FirstOrDefault(x => x.Xor(vin.Image)) is not null)
            {
                validationResults.Add(new ValidationResult("Duplicate image key exists", new[] { "vin" }));
                return validationResults;
            }
            duplicateInputs.Add(vin.Image);
        }

        return validationResults;
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="validationResults"></param>
    /// <param name="vOutputs"></param>
    /// <returns></returns>
    private IEnumerable<ValidationResult> HasDuplicateOutputs(List<ValidationResult> validationResults, Vout[] vOutputs)
    {
        var duplicateOutputs = new List<byte[]>();
        if (vOutputs.Length == 1 && vOutputs[0].T == CoinType.System) return validationResults;
        foreach (var vout in vOutputs)
        {
            if (duplicateOutputs.FirstOrDefault(x => x.Xor(vout.C)) is not null)
            {
                validationResults.Add(new ValidationResult("Duplicate commitment exists", new[] { "vout" }));
                return validationResults;
            }

            duplicateOutputs.Add(vout.C);
            if (vout.E.Length != 9 && !vout.E.Xor("OP_RETURN".ToBytes()))
            {
                if (duplicateOutputs.FirstOrDefault(x => x.Xor(vout.E)) is not null)
                {
                    validationResults.Add(new ValidationResult("Duplicate ephemeral key exists", new[] { "vout" }));
                    return validationResults;
                }

                duplicateOutputs.Add(vout.E);
            }

            if (duplicateOutputs.FirstOrDefault(x => x.Xor(vout.N)) is not null)
            {
                validationResults.Add(new ValidationResult("Duplicate encrypted message exists", new[] { "vout" }));
                return validationResults;
            }

            duplicateOutputs.Add(vout.N);
            if (duplicateOutputs.FirstOrDefault(x => x.Xor(vout.P)) is not null)
            {
                validationResults.Add(new ValidationResult("Duplicate onetime Key exists", new[] { "vout" }));
                return validationResults;
            }

            duplicateOutputs.Add(vout.P);
            if (vout.D.Length != 0)
                if (duplicateOutputs.FirstOrDefault(x => x.Xor(vout.D)) is not null)
                {
                    validationResults.Add(new ValidationResult("Duplicate blind Key exists", new[] { "vout" }));
                    return validationResults;
                }

            duplicateOutputs.Add(vout.D);
            if (vout.S.Length != 0)
                if (duplicateOutputs.FirstOrDefault(x => x.Xor(vout.S)) is not null)
                {
                    validationResults.Add(new ValidationResult("Duplicate script Key exists", new[] { "vout" }));
                    return validationResults;
                }

            duplicateOutputs.Add(vout.S);
        }

        return validationResults;
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="validationResults"></param>
    /// <param name="rct"></param>
    /// <returns></returns>
    private IEnumerable<ValidationResult> HasDuplicateRing(List<ValidationResult> validationResults, Rct[] rct)
    {
        var duplicateRings = new List<byte[]>();
        foreach (var ring in rct)
        {
            if (duplicateRings.FirstOrDefault(x => x.Xor(ring.I)) is not null)
            {
                validationResults.Add(new ValidationResult("Duplicate preimage Key exists", new[] { "rct" }));
                return validationResults;
            }

            duplicateRings.Add(ring.I);
            if (duplicateRings.FirstOrDefault(x => x.Xor(ring.S)) is not null)
            {
                validationResults.Add(new ValidationResult("Duplicate offset signature Key exists", new[] { "rct" }));
                return validationResults;
            }

            duplicateRings.Add(ring.S);
            if (duplicateRings.FirstOrDefault(x => x.Xor(ring.M)) is not null)
            {
                validationResults.Add(new ValidationResult("Duplicate signature Key exists", new[] { "rct" }));
                return validationResults;
            }

            duplicateRings.Add(ring.S);
            if (duplicateRings.FirstOrDefault(x => x.Xor(ring.P)) is not null)
            {
                validationResults.Add(new ValidationResult("Duplicate pc Key exists", new[] { "rct" }));
                return validationResults;
            }

            duplicateRings.Add(ring.P);
        }

        return validationResults;
    }
}