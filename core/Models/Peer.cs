// Tangram by Matthew Hellyer is licensed under CC BY-NC-ND 4.0.
// To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0

using System;
using TangramXtgm.Extensions;
using MessagePack;

namespace TangramXtgm.Models;

[MessagePackObject, Serializable]
public struct Peer : IComparable<Peer>
{
    [Key(0)] public byte[] IpAddress { get; init; }
    [Key(1)] public uint NodeId { get; init; }
    [Key(2)] public byte[] TcpPort { get; set; }
    [Key(3)] public byte[] Name { get; set; }
    [Key(4)] public byte[] PublicKey { get; set; }
    [Key(5)] public byte[] Version { get; set; }

    /// <summary>
    /// </summary>s
    /// <param name="other"></param>
    /// <returns></returns>
    public int CompareTo(Peer other)
    {
        if (Equals(this, other)) return 0;
        if (Equals(null, other)) return 1;
        return IpAddress.Xor(other.IpAddress) ? 0 : 1;
    }

    /// <summary>
    /// </summary>
    /// <returns></returns>
    public override int GetHashCode()
    {
        return HashCode.Combine(IpAddress, Name, Version, PublicKey);
    }
}