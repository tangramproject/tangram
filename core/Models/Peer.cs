﻿// CypherNetwork by Matthew Hellyer is licensed under CC BY-NC-ND 4.0.
// To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0

using System;
using CypherNetwork.Extensions;
using MessagePack;

namespace CypherNetwork.Models;

[MessagePackObject, Serializable]
public struct Peer : IComparable<Peer>
{
    [Key(0)] public byte[] IpAddress { get; init; }
    [Key(1)] public byte[] HttpPort { get; init; }
    [Key(2)] public byte[] HttpsPort { get; init; }
    [Key(3)] public ulong BlockCount { get; set; }
    [Key(4)] public ulong ClientId { get; init; }
    [Key(5)] public byte[] TcpPort { get; set; }
    [Key(6)] public byte[] WsPort { get; set; }
    [Key(7)] public byte[] Name { get; set; }
    [Key(8)] public byte[] PublicKey { get; set; }
    [Key(9)] public byte[] Version { get; set; }
    [Key(10)] public long Timestamp { get; set; }

    /// <summary>
    /// </summary>
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