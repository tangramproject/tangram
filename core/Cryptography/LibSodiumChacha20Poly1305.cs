using System.Runtime.InteropServices;
using System.Security;

namespace TangramXtgm.Cryptography;

/// <summary>
/// LibSodiumChacha20Poly1305 is a static class that provides methods for encrypting and decrypting data using the ChaCha20-Poly1305 authenticated encryption algorithm from the LibS
/// odium library.
/// </summary>
internal static class LibSodiumChacha20Poly1305
{
    /// <summary>
    /// Encrypts a message using the ChaCha20-Poly1305 AEAD encryption algorithm.
    /// </summary>
    /// <param name="c">A pointer to the buffer where the ciphertext will be stored.</param>
    /// <param name="clen_p">A pointer to the length variable of the ciphertext buffer.</param>
    /// <param name="m">A pointer to the message to be encrypted.</param>
    /// <param name="mlen">The length of the message.</param>
    /// <param name="ad">A pointer to the additional authenticated data.</param>
    /// <param name="adlen">The length of the additional authenticated data.</param>
    /// <param name="nsec">Unused parameter.</param>
    /// <param name="npub">A pointer to the nonce.</param>
    /// <param name="k">A pointer to the secret key.</param>
    /// <returns>Returns 0 if the encryption is successful; otherwise, returns a non-zero value.</returns>
    [SuppressUnmanagedCodeSecurity]
    [DllImport("libsodium", CallingConvention = CallingConvention.Cdecl,
        EntryPoint = "crypto_aead_chacha20poly1305_encrypt")]
    internal static extern unsafe int Encrypt(
        byte* c,
        ulong* clen_p,
        byte* m,
        ulong mlen,
        byte* ad,
        ulong adlen,
        byte* nsec,
        byte* npub,
        byte* k);

    /// <summary>
    /// Decrypts the given ciphertext using the ChaCha20-Poly1305 encryption algorithm.
    /// </summary>
    /// <param name="m">Pointer to store the decrypted message.</param>
    /// <param name="mlen_p">Reference to a ulong variable to store the length of the decrypted message.</param>
    /// <param name="nsec">Pointer to a secret nonce (optional).</param>
    /// <param name="c">Pointer to the ciphertext to be decrypted.</param>
    /// <param name="clen">Length of the ciphertext.</param>
    /// <param name="ad">Pointer to additional data to authenticate (optional).</param>
    /// <param name="adlen">Length of the additional data.</param>
    /// <param name="npub">Pointer to the nonce and public key.</param>
    /// <param name="k">Pointer to the secret key.</param>
    /// <returns>Returns 0 on success, or a negative value if decryption fails.</returns>
    [SuppressUnmanagedCodeSecurity]
    [DllImport("libsodium", CallingConvention = CallingConvention.Cdecl,
        EntryPoint = "crypto_aead_chacha20poly1305_decrypt")]
    internal static extern unsafe int Decrypt(
        byte* m,
        ref ulong mlen_p,
        byte* nsec,
        byte* c,
        ulong clen,
        byte* ad,
        ulong adlen,
        byte* npub,
        byte* k);
}