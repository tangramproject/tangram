// Tangram by Matthew Hellyer is licensed under CC BY-NC-ND 4.0.
// To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0

using System;
using MessagePack;
using TangramXtgm.Extensions;
using TangramXtgm.Network;

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
    [Key(6)] public PeerState PeerState { get; set; }
    [IgnoreMember] public DateTime ReceivedDateTime { get; set; }
    [IgnoreMember] public bool IsSeed { get; set; }

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

    /// <summary>
    /// 
    /// </summary>
    /// <returns></returns>
    public byte[] Serialize()
    {
        return MessagePackSerializer.Serialize(this);
    }

    /// <summary>
    /// Gets the description of a given PeerState.
    /// </summary>
    /// <param name="state">The PeerState for which to get the description.</param>
    /// <returns>The description of the given PeerState.</returns>
    public static string GetPeerStateDescription(PeerState state)
    {
        switch (state)
        {
            case PeerState.Alive:
                return "Alive";
            case PeerState.Dead:
                return "Dead";
            case PeerState.Suspicious:
                return "Suspicious";
            case PeerState.Retry:
                return "Retrying";
            case PeerState.Unreachable:
                return "Unreachable";
            case PeerState.DupBlocks:
                return "Duplicate Blocks";
            case PeerState.OrphanBlock:
                return "Orphan Block";
            case PeerState.Left:
                return "Left";
            case PeerState.Pruned:
                return "Pruned";
            case PeerState.Ready:
                return "Ready";
            default:
                return "Unknown peer state";
        }
    }
}