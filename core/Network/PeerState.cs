// Tangram by Matthew Hellyer is licensed under CC BY-NC-ND 4.0.
// To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0

namespace TangramXtgm.Network;

public enum PeerState : byte
{
    Alive = 0x00,
    Dead = 0x01,
    Suspicious = 0x02,
    Retry = 0x03,
    Unreachable = 0x04,
    DupBlocks = 0x05,
    OrphanBlock = 0x06,
    Ready = 0x99
}