// Tangram by Matthew Hellyer is licensed under CC BY-NC-ND 4.0.
// To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0

using MessagePack;
using TangramXtgm.Models.Messages;

namespace TangramXtgm.Models;

[MessagePackObject]
public record Parameter
{
    [Key(0)] public byte[] Value { get; init; }
    [Key(1)] public ProtocolCommand ProtocolCommand { get; init; }
    [IgnoreMember] public byte[] Sender { get; set; }
}