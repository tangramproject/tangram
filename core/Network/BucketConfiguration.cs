using System;

namespace TangramXtgm.Network;

public class BucketConfiguration
{
    public int MaxFill { get; set; }
    public TimeSpan LeakRateTimeSpan { get; set; }
    public int LeakRate { get; set; }
}