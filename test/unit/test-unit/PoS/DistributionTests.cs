// Tangram by Matthew Hellyer is licensed under CC BY-NC-ND 4.0.
// To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0

using System;
using TangramXtgm.Extensions;
using TangramXtgm.Models;
using libsignal.ecc;
using NBitcoin.BouncyCastle.Math;
using NUnit.Framework;

namespace xtgmcore_test_unit.PoS;

public class DistributionTests
{
    private const decimal Distribution = 21_000_000;

    [Test]
    public void PosDistribution()
    {
        var solu = 491383ul;
        var runningDistribution = Distribution;
        runningDistribution -= NetworkShare(solu, runningDistribution);
        var netShare = NetworkShare(solu, runningDistribution);
        runningDistribution -= netShare;

        var v1 = VerifyNetworkShare(solu, netShare, runningDistribution);

        Assert.True(v1 == VerifyResult.Succeed ? true : false);

        netShare = NetworkShare(5972130, runningDistribution);
        runningDistribution = CurrentRunningDistribution(netShare, runningDistribution);
        var v2 = VerifyNetworkShare(5972130, netShare, runningDistribution);

        Assert.True(v2 == VerifyResult.Succeed ? true : false);

        for (var i = 0; i < 10; i++)
        {
            var keyPair = TangramXtgm.Cryptography.Crypto.GenerateKeyPair();
            var hash = NBitcoin.Crypto.Hashes.DoubleSHA256(new byte[i]);
            var calculateVrfSignature =
                Curve.calculateVrfSignature(Curve.decodePrivatePoint(keyPair.PrivateKey), hash.ToBytes(false));
            var verifyVrfSignature = Curve.verifyVrfSignature(Curve.decodePoint(keyPair.PublicKey, 0),
                hash.ToBytes(false), calculateVrfSignature);
            var solution = Solution(verifyVrfSignature, hash.ToBytes(false));
            var networkShare = NetworkShare(solution, runningDistribution);
            var reward = Reward(solution, runningDistribution);
            var bits = Difficulty(solution, networkShare);

            runningDistribution = CurrentRunningDistribution(networkShare, runningDistribution);
            var verifyNetworkShare = VerifyNetworkShare(solution, networkShare, runningDistribution);

            Assert.True(verifyNetworkShare == VerifyResult.Succeed ? true : false);
        }
    }

    private static ulong Solution(byte[] vrfSig, byte[] kernel)
    {
        var calculating = true;
        long itr = 0;

        var target = new BigInteger(1, vrfSig);
        var hashTarget = new BigInteger(1, kernel);

        var hashTargetValue = new BigInteger((target.IntValue / hashTarget.BitCount).ToString()).Abs();
        var hashWeightedTarget = new BigInteger(1, kernel).Multiply(hashTargetValue);

        while (calculating)
        {
            var weightedTarget = target.Multiply(BigInteger.ValueOf(itr));
            if (hashWeightedTarget.CompareTo(weightedTarget) <= 0) calculating = false;

            itr++;
        }

        return (ulong)itr;
    }

    private static decimal CurrentRunningDistribution(decimal networkShare, decimal prevRunningDistribution)
    {
        var runningDistribution = prevRunningDistribution;
        runningDistribution -= networkShare;

        return runningDistribution;
    }

    private static decimal NetworkShare(ulong solution, decimal runningDistribution)
    {
        var r = Distribution - runningDistribution;
        var percentage = r / runningDistribution == 0 ? 0.1M : r / runningDistribution;
        if (percentage != 0.1M)
        {
            percentage += percentage * Convert.ToDecimal("1".PadRight(percentage.LeadingZeros(), '0'));
        }

        return solution * percentage / Distribution;
    }

    private static ulong Reward(ulong solution, decimal runningDistribution)
    {
        var networkShare = NetworkShare(solution, runningDistribution);
        return networkShare.ConvertToUInt64();
    }

    private static int Difficulty(ulong solution, decimal networkShare)
    {
        var diff = Math.Truncate(solution * networkShare / 144);
        diff = diff == 0 ? 1 : diff;

        return (int)diff;
    }

    private static VerifyResult VerifyNetworkShare(ulong solution, decimal previousNetworkShare,
        decimal runningDistributionTotal)
    {
        var previousRunningDistribution = runningDistributionTotal + previousNetworkShare;
        if (previousRunningDistribution > Distribution) return VerifyResult.UnableToVerify;

        var networkShare = NetworkShare(solution, previousRunningDistribution).ConvertToUInt64().DivCoin();
        previousNetworkShare = previousNetworkShare.ConvertToUInt64().DivCoin();

        return networkShare == previousNetworkShare ? VerifyResult.Succeed : VerifyResult.UnableToVerify;
    }
}