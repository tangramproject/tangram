// Tangram by Matthew Hellyer is licensed under CC BY-NC-ND 4.0.
// To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0

using System;
using MessagePack;

namespace TangramXtgm.Models;

/// <summary>
/// 
/// </summary>
[MessagePackObject, Serializable]
public record LocalNode
{
    [Key(0)] public ulong NodeId { get; init; }
    [Key(1)] public byte[] PublicKey { get; init; }
    [Key(2)] public byte[] Name { get; init; }
    [Key(3)] public byte[] TcpPort { get; init; }
    [Key(4)] public byte[] WsPort { get; init; }
    [Key(5)] public byte[] HttpPort { get; init; }
    [Key(6)] public byte[] HttpsPort { get; init; }
    [Key(7)] public byte[] IpAddress { get; init; }
    [Key(8)] public byte[] Version { get; init; }
}