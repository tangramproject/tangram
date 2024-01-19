using System.Runtime.InteropServices;
using System.Security;

namespace TangramXtgm.Cryptography;

/// <summary>
/// Provides methods for cryptographic operations using LibSodium.
/// This class should not be instantiated.
/// </summary>
internal static class LibSodiumBox
{
    /// <summary>
    /// Seals a message using the given public key.
    /// </summary>
    /// <param name="c">The pointer to store the sealed ciphertext.</param>
    /// <param name="m">The pointer to the message to be sealed.</param>
    /// <param name="mlen">The length of the message.</param>
    /// <param name="pk">The pointer to the recipient's public key.</param>
    /// <returns>Returns 0 if the sealing operation is successful; otherwise, returns a non-zero value.</returns>
    [SuppressUnmanagedCodeSecurity]
    [DllImport("libsodium", CallingConvention = CallingConvention.Cdecl, EntryPoint = "crypto_box_seal")]
    internal static extern unsafe int Seal(byte* c, byte* m, ulong mlen, byte* pk);

    /// <summary>
    /// Verifies and opens a sealed box using the given public and secret keys.
    /// </summary>
    /// <param name="m">A pointer to the output buffer where the decrypted message will be written.</param>
    /// <param name="c">A pointer to the sealed box containing the encrypted message.</param>
    /// <param name="clen">The length of the sealed box in bytes.</param>
    /// <param name="pk">A pointer to the public key used for sealing the box.</param>
    /// <param name="sk">A pointer to the secret key used for opening the box.</param>
    /// <returns>
    /// Returns 0 if the sealed box was successfully opened and the decrypted message was written to the output buffer.
    /// If the sealed box fails verification, or an error occurs, a non-zero integer is returned.
    /// </returns>
    [SuppressUnmanagedCodeSecurity]
    [DllImport("libsodium", CallingConvention = CallingConvention.Cdecl, EntryPoint = "crypto_box_seal_open")]
    internal static extern unsafe int SealOpen(
        byte* m,
        byte* c,
        ulong clen,
        byte* pk,
        byte* sk);

    /// <summary>
    /// Returns the number of bytes required to store a sealed box.
    /// </summary>
    /// <returns>The number of bytes.</returns>
    [SuppressUnmanagedCodeSecurity]
    [DllImport("libsodium", CallingConvention = CallingConvention.Cdecl, EntryPoint = "crypto_box_sealbytes")]
    internal static extern ulong Sealbytes();
}