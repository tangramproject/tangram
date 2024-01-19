// Tangram by Matthew Hellyer is licensed under CC BY-NC-ND 4.0.
// To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0

using System;
using System.Security.Cryptography;
using System.Threading.Tasks;
using TangramXtgm.Extensions;
using Dawn;
using Libsecp256k1Zkp.Net;
using libsignal.ecc;
using Microsoft.AspNetCore.DataProtection;
using Newtonsoft.Json;
using Serilog;
using TangramXtgm.Models;
using TangramXtgm.Models.Messages;
using TangramXtgm.Persistence;

namespace TangramXtgm.Cryptography;

/// <summary>
/// Represents an interface for performing cryptographic operations.
/// </summary>
public interface ICrypto
{
    Task<Models.KeyPair> GetOrUpsertKeyNameAsync(string keyName);
    Task<byte[]> GetPublicKeyAsync(string keyName);
    Task<SignatureResponse> SignAsync(string keyName, byte[] message);
    byte[] SignXEdDSA(byte[] privateKey, byte[] message);
    byte[] SignSchnorr(byte[] privateKey, byte[] message);
    bool VerifyXEdDSASignature(byte[] signature, byte[] message, byte[] publicKey);
    bool VerifySchnorr(byte[] publicKey, byte[] message, byte[] signature);
    bool VerifySchnorrBatch(byte[][] publicKeys, byte[][] messages, byte[][] signatures);
    bool VerifySignature(byte[] publicKey, byte[] message, byte[] signature);
    byte[] GetCalculateVrfSignature(ECPrivateKey ecPrivateKey, byte[] msg);
    byte[] GetVerifyVrfSignature(ECPublicKey ecPublicKey, byte[] msg, byte[] sig);
    // byte[] EncryptChaCha20Poly1305(byte[] data, byte[] key, byte[] associatedData, out byte[] tag, out byte[] nonce);
    byte[] DecryptChaCha20Poly1305(ReadOnlyMemory<byte> data, ReadOnlyMemory<byte> key,
        ReadOnlyMemory<byte> associatedData, ReadOnlyMemory<byte> tag, ReadOnlyMemory<byte> nonce);
    byte[] BoxSeal(ReadOnlySpan<byte> msg, ReadOnlySpan<byte> publicKey);
    byte[] BoxSealOpen(ReadOnlySpan<byte> cipher, ReadOnlySpan<byte> secretKey, ReadOnlySpan<byte> publicKey);
}

/// <summary>
/// Provides cryptographic operations including key generation, signing, and verification.
/// </summary>
public class Crypto : ICrypto
{
    private readonly IDataProtectionProvider _dataProtectionProvider;
    private readonly ILogger _logger;
    private readonly IUnitOfWork _unitOfWork;

    private IDataProtector _dataProtector;
    private DataProtection _protectionProto;

    /// <summary>
    /// Represents a class for cryptographic operations.
    /// </summary>
    /// <param name="dataProtectionProvider">An instance of the IDataProtectionProvider interface used for data protection.</param>
    /// <param name="unitOfWork">An instance of the IUnitOfWork interface used for managing database transactions.</param>
    /// <param name="logger">An instance of the ILogger interface used for logging.</param>
    public Crypto(IDataProtectionProvider dataProtectionProvider, IUnitOfWork unitOfWork, ILogger logger)
    {
        _dataProtectionProvider = dataProtectionProvider;
        _unitOfWork = unitOfWork;
        _logger = logger.ForContext("SourceContext", nameof(Crypto));
    }

    /// <summary>
    /// Retrieves the existing KeyPair associated with the specified key name, or creates and saves a new KeyPair if one does not exist.
    /// </summary>
    /// <param name="keyName">The name of the key for which to retrieve or create a KeyPair.</param>
    /// <returns>The KeyPair associated with the specified key name, or null if an error occurred.</returns>
    public async Task<Models.KeyPair> GetOrUpsertKeyNameAsync(string keyName)
    {
        Guard.Argument(keyName, nameof(keyName)).NotNull().NotWhiteSpace();
        Models.KeyPair kp = null;
        try
        {
            _dataProtector = _dataProtectionProvider.CreateProtector(keyName);
            _protectionProto = await _unitOfWork.DataProtectionPayload.GetAsync(keyName.ToBytes());
            if (_protectionProto == null)
            {
                _protectionProto = new DataProtection
                {
                    FriendlyName = keyName,
                    Payload = _dataProtector.Protect(JsonConvert.SerializeObject(GenerateKeyPair()))
                };
                var saved = await _unitOfWork.DataProtectionPayload.PutAsync(keyName.ToBytes(), _protectionProto);
                if (!saved)
                {
                    _logger.Here().Error("Unable to save protection key payload for: {@KeyName}", keyName);
                    return null;
                }
            }

            kp = GetKeyPair();
        }
        catch (CryptographicException ex)
        {
            _logger.Here().Fatal(ex, "Cannot get keypair");
        }
        catch (Exception ex)
        {
            _logger.Here().Error(ex, "Cannot get keypair");
        }

        return kp;
    }

    /// <summary>
    /// Retrieves the public key asynchronously for the specified key name.
    /// </summary>
    /// <param name="keyName">The name of the key to retrieve the public key for.</param>
    /// <returns>The public key byte array of the specified key name. If the key name does not exist, returns null.</returns>
    public async Task<byte[]> GetPublicKeyAsync(string keyName)
    {
        var kp = await GetOrUpsertKeyNameAsync(keyName);
        return kp?.PublicKey;
    }

    /// <summary>
    /// SignAsync method is used to sign the given message using the provided keyName.
    /// </summary>
    /// <param name="keyName">The name of the key to be used for signing.</param>
    /// <param name="message">The byte array of the message to be signed.</param>
    /// <returns>Returns a Task object of type SignatureResponse.</returns>
    public async Task<SignatureResponse> SignAsync(string keyName, byte[] message)
    {
        Guard.Argument(keyName, nameof(keyName)).NotNull().NotWhiteSpace();
        Guard.Argument(message, nameof(message)).NotNull();
        SignatureResponse signatureResponse = null;
        try
        {
            var keyPair = await GetOrUpsertKeyNameAsync(keyName);
            var signature = Curve.calculateSignature(Curve.decodePrivatePoint(keyPair.PrivateKey), message);
            signatureResponse = new SignatureResponse(signature, keyPair.PublicKey);
        }
        catch (Exception ex)
        {
            _logger.Here().Error(ex, "Unable to sign the message");
        }

        return signatureResponse;
    }

    /// <summary>
    /// Signs a message using the XEdDSA algorithm.
    /// </summary>
    /// <param name="privateKey">The private key used for signing.</param>
    /// <param name="message">The message to be signed.</param>
    /// <returns>The signature of the message.</returns>
    public byte[] SignXEdDSA(byte[] privateKey, byte[] message)
    {
        Guard.Argument(privateKey, nameof(privateKey)).NotNull().MaxCount(32);
        Guard.Argument(message, nameof(message)).NotNull().MaxCount(32);
        return Curve.calculateSignature(Curve.decodePrivatePoint(privateKey), message);
    }

    /// <summary>
    /// Signs a message using the Schnorr algorithm.
    /// </summary>
    /// <param name="privateKey">The private key used to sign the message. Must not be null and have a maximum length of 32 bytes.</param>
    /// <param name="message">The message to be signed. Must not be null and have a maximum length of 32 bytes.</param>
    /// <returns>The signature generated for the message as a byte array.</returns>
    public byte[] SignSchnorr(byte[] privateKey, byte[] message)
    {
        Guard.Argument(privateKey, nameof(privateKey)).NotNull().MaxCount(32);
        Guard.Argument(message, nameof(message)).NotNull().MaxCount(32);
        using var schnorrSig = new Schnorr();
        var msgHash = SHA256.Create().ComputeHash(message);
        var sig = schnorrSig.Sign(msgHash, privateKey);
        return sig;
    }

    /// <summary>
    /// Verifies a Schnorr signature.
    /// </summary>
    /// <param name="publicKey">The public key.</param>
    /// <param name="message">The message.</param>
    /// <param name="signature">The signature.</param>
    /// <returns>True if the signature is valid; otherwise, false.</returns>
    public bool VerifySchnorr(byte[] publicKey, byte[] message, byte[] signature)
    {
        Guard.Argument(publicKey, nameof(publicKey)).NotNull().MaxCount(32);
        Guard.Argument(message, nameof(message)).NotNull().MaxCount(32);
        Guard.Argument(signature, nameof(signature)).NotNull().MaxCount(64);
        using var schnorrSig = new Schnorr();
        var msgHash = SHA256.Create().ComputeHash(message);
        var verified = schnorrSig.Verify(signature, msgHash, publicKey);
        return verified;
    }

    /// <summary>
    /// Verifies a batch of Schnorr signatures.
    /// </summary>
    /// <param name="publicKeys">An array of byte arrays representing the public keys used for verification.</param>
    /// <param name="messages">An array of byte arrays representing the messages to be verified.</param>
    /// <param name="signatures">An array of byte arrays representing the signatures to be verified.</param>
    /// <returns>True if all signatures are valid, False otherwise.</returns>
    public bool VerifySchnorrBatch(byte[][] publicKeys, byte[][] messages, byte[][] signatures)
    {
        Guard.Argument(publicKeys, nameof(publicKeys)).NotNull().NotEmpty();
        Guard.Argument(messages, nameof(messages)).NotNull().NotEmpty();
        Guard.Argument(signatures, nameof(signatures)).NotNull().NotEmpty();
        Guard.Argument(publicKeys.Length, nameof(publicKeys.Length)).Equals(messages.Length);
        Guard.Argument(publicKeys.Length, nameof(publicKeys.Length)).Equals(signatures.Length);
        using var schnorrSig = new Schnorr();
        var msgHashes = new byte[messages.Length][];
        for (var i = 0; i < messages.Length; i++)
        {
            msgHashes[i] = SHA256.Create().ComputeHash(messages[i]);
        }
        var verified = schnorrSig.VerifyBatch(signatures, msgHashes, publicKeys);
        return verified;
    }

    /// <summary>
    /// Verifies the XEdDSA signature.
    /// </summary>
    /// <param name="signature">The signature to verify.</param>
    /// <param name="message">The message that was signed.</param>
    /// <param name="publicKey">The public key used for verification.</param>
    /// <returns>Returns true if the signature is valid, otherwise false.</returns>
    public bool VerifyXEdDSASignature(byte[] signature, byte[] message, byte[] publicKey)
    {
        Guard.Argument(signature, nameof(signature)).NotNull().MaxCount(64);
        Guard.Argument(message, nameof(message)).NotNull().MaxCount(32);
        Guard.Argument(publicKey, nameof(publicKey)).NotNull().MaxCount(33);

        var verified = false;
        try
        {
            verified = Curve.verifySignature(Curve.decodePoint(publicKey, 0), message, signature);
        }
        catch (Exception ex)
        {
            _logger.Here().Error(ex, "Cannot verify signature");
        }

        return verified;
    }

    /// <summary>
    /// Verifies the signature using the provided public key, message, and signature.
    /// </summary>
    /// <param name="publicKey">The public key used for signature verification.</param>
    /// <param name="message">The message to be verified.</param>
    /// <param name="signature">The signature to be verified.</param>
    /// <returns>True if the signature is valid, otherwise false.</returns>
    public bool VerifySignature(byte[] publicKey, byte[] message, byte[] signature)
    {
        Guard.Argument(publicKey, nameof(publicKey)).NotNull();
        Guard.Argument(message, nameof(message)).NotNull();
        Guard.Argument(signature, nameof(signature)).NotNull();
        var verified = false;
        try
        {
            verified = Curve.verifySignature(Curve.decodePoint(publicKey, 0), message, signature);
        }
        catch (Exception ex)
        {
            _logger.Here().Error(ex, "Cannot verify signature");
        }

        return verified;
    }

    /// <summary>
    /// Calculates the VRF signature using the provided EC private key and message.
    /// </summary>
    /// <param name="ecPrivateKey">The EC private key used for the VRF calculation.</param>
    /// <param name="msg">The message to be signed.</param>
    /// <returns>The calculated VRF signature as a byte array.</returns>
    public byte[] GetCalculateVrfSignature(ECPrivateKey ecPrivateKey, byte[] msg)
    {
        Guard.Argument(ecPrivateKey, nameof(ecPrivateKey)).NotNull();
        Guard.Argument(msg, nameof(msg)).NotNull().NotEmpty();
        var calculateVrfSignature = Curve.calculateVrfSignature(ecPrivateKey, msg);
        return calculateVrfSignature;
    }

    /// <summary>
    /// Verifies the VRF signature using the provided public key, message, and signature.
    /// </summary>
    /// <param name="ecPublicKey">The EC public key used to verify the signature.</param>
    /// <param name="msg">The message that was signed.</param>
    /// <param name="sig">The signature to verify.</param>
    /// <returns>The verified VRF signature as a byte array.</returns>
    public byte[] GetVerifyVrfSignature(ECPublicKey ecPublicKey, byte[] msg, byte[] sig)
    {
        Guard.Argument(ecPublicKey, nameof(ecPublicKey)).NotNull();
        Guard.Argument(sig, nameof(sig)).NotNull().NotEmpty();
        Guard.Argument(msg, nameof(msg)).NotNull().NotEmpty();
        var vrfSignature = Curve.verifyVrfSignature(ecPublicKey, msg, sig);
        return vrfSignature;
    }

    // public byte[] EncryptChaCha20Poly1305(byte[] data, byte[] key, byte[] associatedData, out byte[] tag,
    //     out byte[] nonce)
    // {
    //     tag = new byte[Chacha20poly1305.Abytes()];
    //     nonce = GetRandomData();
    //     var cipherText = new byte[data.Length + (int)Chacha20poly1305.Abytes()];
    //     var cipherTextLength = 0ul;
    //     return Chacha20poly1305.Encrypt(cipherText, ref cipherTextLength, data, (ulong)data.Length,
    //         associatedData, (ulong)associatedData.Length, null, nonce, key) != 0
    //         ? Array.Empty<byte>()
    //         : cipherText;
    // }

    /// <summary>
    /// Decrypts data using the ChaCha20-Poly1305 encryption algorithm.
    /// </summary>
    /// <param name="data">The data to be decrypted.</param>
    /// <param name="key">The encryption key.</param>
    /// <param name="associatedData">The additional associated data.</param>
    /// <param name="tag">The authentication tag.</param>
    /// <param name="nonce">The initialization nonce.</param>
    /// <returns>The decrypted data.</returns>
    public unsafe byte[] DecryptChaCha20Poly1305(ReadOnlyMemory<byte> data, ReadOnlyMemory<byte> key,
        ReadOnlyMemory<byte> associatedData, ReadOnlyMemory<byte> tag, ReadOnlyMemory<byte> nonce)
    {
        var decryptedData = stackalloc byte[data.Length];
        var decryptedDataLength = 0ul;
        int result;
        fixed (byte* dPtr = data.Span, aPrt = associatedData.Span, nPrt = nonce.Span, kPrt = key.Span)
        {
            result = LibSodiumChacha20Poly1305.Decrypt(decryptedData, ref decryptedDataLength, null, dPtr,
                (ulong)data.Length, aPrt, (ulong)associatedData.Length, nPrt, kPrt);
        }

        var destination = new Span<byte>(decryptedData, (int)decryptedDataLength);
        return result != 0 ? Array.Empty<byte>() : destination.Slice(0, (int)decryptedDataLength).ToArray();
    }

    /// <summary>
    /// Decrypts a ciphertext using a secret key and a public key.
    /// </summary>
    /// <param name="cipher">The ciphertext to be decrypted.</param>
    /// <param name="secretKey">The secret key used for decryption.</param>
    /// <param name="publicKey">The public key used for decryption.</param>
    /// <returns>The decrypted message as a byte array.</returns>
    public unsafe byte[] BoxSealOpen(ReadOnlySpan<byte> cipher, ReadOnlySpan<byte> secretKey,
        ReadOnlySpan<byte> publicKey)
    {
        var len = cipher.Length - (int)LibSodiumBox.Sealbytes();
        //var msg = stackalloc byte[len];
        var msg = new byte[len];
        int result;
        fixed (byte* m = msg, cPtr = cipher, pkPtr = publicKey, skPtr = secretKey)
        {
            result = LibSodiumBox.SealOpen(m, cPtr, (ulong)cipher.Length, pkPtr, skPtr);
        }

        // var destination = new Span<byte>(msg, len);
        // return result != 0 ? Array.Empty<byte>() : destination.Slice(0, len).ToArray();

        return result != 0 ? Array.Empty<byte>() : msg;
    }

    /// <summary>
    /// Encrypts a message using the provided public key.
    /// </summary>
    /// <param name="msg">The message to be encrypted.</param>
    /// <param name="publicKey">The public key used for encryption.</param>
    /// <returns>The encrypted message as a byte array. If encryption fails, an empty byte array is returned.</returns>
    public unsafe byte[] BoxSeal(ReadOnlySpan<byte> msg, ReadOnlySpan<byte> publicKey)
    {
        var cipher = new byte[msg.Length + (int)LibSodiumBox.Sealbytes()];
        var result = 0;
        fixed (byte* mPtr = msg, cPtr = cipher, pkPtr = publicKey)
        {
            result = LibSodiumBox.Seal(cPtr, mPtr, (ulong)msg.Length, pkPtr);
        }

        return result != 0 ? Array.Empty<byte>() : cipher;
    }

    /// <summary>
    /// Generates a key pair using Curve.generateKeyPair and returns it.
    /// </summary>
    /// <returns>Returns a KeyPair object containing the generated private and public keys.</returns>
    public static Models.KeyPair GenerateKeyPair()
    {
        var keys = Curve.generateKeyPair();
        return new Models.KeyPair(keys.getPrivateKey().serialize(), keys.getPublicKey().serialize());
    }

    /// <summary>
    /// Generates a random byte array using the Secp256k1 algorithm.
    /// </summary>
    /// <returns>A random byte array.</returns>
    public static byte[] GetRandomData()
    {
        using var secp256K1 = new Secp256k1();
        return secp256K1.RandomSeed();
    }

    /// <summary>
    /// Retrieves a KeyPair object containing a private key and a public key.
    /// </summary>
    /// <returns>The KeyPair object.</returns>
    private Models.KeyPair GetKeyPair()
    {
        Guard.Argument(_protectionProto, nameof(_protectionProto)).NotNull();
        Guard.Argument(_protectionProto.Payload, nameof(_protectionProto.Payload)).NotNull().NotWhiteSpace();
        var unprotectedPayload = _dataProtector.Unprotect(_protectionProto.Payload);
        var definition = new { PrivateKey = string.Empty, PublicKey = string.Empty };
        var message = JsonConvert.DeserializeAnonymousType(unprotectedPayload, definition);
        return new Models.KeyPair(Convert.FromBase64String(message.PrivateKey),
            Convert.FromBase64String(message.PublicKey));
    }
}