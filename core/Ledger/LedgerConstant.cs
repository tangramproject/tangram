// Tangram by Matthew Hellyer is licensed under CC BY-NC-ND 4.0.
// To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0

using Dawn;
using TangramXtgm.Extensions;

namespace TangramXtgm.Ledger;

public static class LedgerConstant
{
    public const int MagicNumber = 860243278;

    // Graph
    public const double
        OnRoundThrottleFromSeconds =
            3.5; // Block size will have an effect. Should increase/decrease.

    // Validator
    public const decimal Distribution = 110_080_100M;
    public const int RewardPercentage = 50;
    public const ulong SolutionThrottle = 7_000_000;
    public const ushort SystemSolutionTime = 5120;
    public const int Coin = 1000_000_000;
    public const int Bits = 8192;
    public const int MBits = 960;
    public static readonly byte[] BlockZeroMerkel =
        "D5C174DCBA402D3EE1701FE9C18156C3CD6D719FDEFE8DAF550CCC39D9689E6B".HexToByte();
    public static readonly byte[] BlockZeroPrevHash =
        "74616E6772616D5854474DAF915782EBC2C2FA70696E67706F6E67736E65616B".HexToByte();

    // Protocol V3
    public const int TransactionV3Height = 19;
    public const int BlockV3Height = 280;

    // PPoS
    public const uint BlockProposalTimeFromSeconds = 5;
    public const uint WaitSyncTimeFromSeconds = 5;
    public const uint WaitPPoSEnabledTimeFromSeconds = 5;
    public const int SlothCancellationTimeoutFromMilliseconds = 120_000;

    // MemPool
    public const uint TransactionDefaultTimeDelayFromSeconds = 5;

    /// <summary>
    /// 
    /// </summary>
    /// <param name="x"></param>
    /// <returns></returns>
    public static int CalculateTimeCost(int x)
    {
        Guard.Argument(x, nameof(x)).NotNegative().NotZero();
        return x switch
        {
            <= 19 => 64,
            >= 19 and <= 38 => 64 * 2,
            >= 38 and <= 57 => 64 * 3,
            >= 57 and <= 76 => 64 * 4,
            >= 76 and <= 95 => 64 * 5,
            >= 95 and <= 114 => 64 * 6,
            >= 114 and <= 133 => 64 * 7,
            _ => 16
        };
    }
}