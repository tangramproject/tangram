// Tangram by Matthew Hellyer is licensed under CC BY-NC-ND 4.0.
// To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0

using TangramXtgm.Helper;

namespace TangramXtgm.Models;

/// <summary>
/// </summary>
public record SeenBlockGraph
{
    public SeenBlockGraph()
    {
        Timestamp = Util.GetAdjustedTimeAsUnixTimestamp();
    }

    public long Timestamp { get; }
    public ulong Round { get; set; }
    public byte[] Hash { get; set; }
}