using MessagePack;

namespace TangramXtgm.Models;

[MessagePackObject]
public record BlockGraphSignature
{
    [Key(0)] public byte[] Signature { get; set; }
    [Key(1)] public byte[] PublicKey { get; set; }
    [Key(2)] public byte[] Message { get; set; }
}