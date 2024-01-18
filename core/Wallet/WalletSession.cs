// Tangram by Matthew Hellyer is licensed under CC BY-NC-ND 4.0.
// To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0

using System;
using System.Collections.Generic;
using System.Linq;
using System.Reactive.Linq;
using System.Security;
using System.Threading.Tasks;
using TangramXtgm.Extensions;
using Dawn;
using MessagePack;
using Microsoft.Extensions.Hosting;
using NBitcoin;
using Serilog;
using TangramXtgm.Models;
using TangramXtgm.Models.Messages;
using TangramXtgm.Persistence;
using TangramXtgm.Wallet.Models;
using Block = TangramXtgm.Models.Block;
using Transaction = TangramXtgm.Models.Transaction;

namespace TangramXtgm.Wallet;

/// <summary>
/// Represents a consumed record.
/// </summary>
public record Consumed(byte[] Commit, DateTime Time)
{
    public readonly DateTime Time = Time;
    public readonly byte[] Commit = Commit;
}

/// <summary>
/// Represents a session for interacting with a wallet.
/// </summary>
public class WalletSession : IWalletSession, IDisposable
{
    private const string HardwarePath = "m/44'/847177'/0'/0/";

    public Caching<Output> CacheTransactions { get; } = new();
    public Cache<Consumed> CacheConsumed { get; } = new();
    public Output Spending { get; set; }
    public SecureString Seed { get; set; }
    public SecureString Passphrase { get; set; }
    public string SenderAddress { get; set; }
    public string RecipientAddress { get; set; }
    public SecureString KeySet { get; set; }
    public ulong Amount { get; set; }
    public ulong Change { get; set; }
    public ulong Reward { get; set; }

    private readonly ISystemCore _systemCore;
    private readonly IHostApplicationLifetime _applicationLifetime;
    private readonly ILogger _logger;
    private readonly NBitcoin.Network _network;

    private IDisposable _disposableHandleSafeguardBlocks;
    private IDisposable _disposableHandelConsumed;
    private bool _disposed;
    private IReadOnlyList<Block> _readOnlySafeGuardBlocks;

    private static readonly object Locking = new();

    /// <summary>
    /// Represents a wallet session.
    /// </summary>
    /// <param name="systemCore">The system core object responsible for managing the wallet session.</param>
    /// <param name="applicationLifetime">The application lifetime object for managing the lifetime of the wallet session.</param>
    /// <param name="logger">The logger object for logging wallet session activities.</param>
    public WalletSession(ISystemCore systemCore, IHostApplicationLifetime applicationLifetime, ILogger logger)
    {
        _systemCore = systemCore;
        _applicationLifetime = applicationLifetime;
        _logger = logger;
        _network = systemCore.Node.Network.Environment == Node.Mainnet
            ? NBitcoin.Network.Main
            : NBitcoin.Network.TestNet;
        Init();
    }

    /// <summary>
    /// Initializes the object.
    /// </summary>
    private void Init()
    {
        HandleSafeguardBlocks();
        HandelConsumed();
    }

    /// <summary>
    /// Notifies the system about the given transactions.
    /// </summary>
    /// <param name="transactions">The array of transactions to be notified.</param>
    public void Notify(Transaction[] transactions)
    {
        if (KeySet is null) return;
        foreach (var consumed in CacheConsumed.GetItems())
        {
            var transaction = transactions.FirstOrDefault(t => t.Vout.Any(c => c.C.Xor(consumed.Commit)));
            if (transaction.IsDefault()) continue;
            CacheConsumed.Remove(consumed.Commit);
            CacheTransactions.Remove(consumed.Commit);
            break;
        }
    }

    /// <summary>
    /// Logs in to the wallet asynchronously using the provided seed.
    /// </summary>
    /// <param name="seed">The seed used for authentication.</param>
    /// <returns>A task that represents the asynchronous login operation. The task result contains a tuple with a boolean indicating whether the login was successful and a string message.</returns>
    public Task<Tuple<bool, string>> LoginAsync(byte[] seed)
    {
        Guard.Argument(seed, nameof(seed)).NotNull().NotEmpty();
        try
        {
            Seed = seed.ToSecureString();
            seed.Destroy();
            CreateHdRootKey(Seed, out var rootKey);
            var keySet = CreateKeySet(new KeyPath($"{HardwarePath}0"), rootKey.PrivateKey.ToHex().HexToByte(),
                rootKey.ChainCode);
            SenderAddress = keySet.StealthAddress;
            KeySet = MessagePackSerializer.Serialize(keySet).ByteToHex().ToSecureString();
            keySet.ChainCode.ZeroString();
            keySet.KeyPath.ZeroString();
            keySet.RootKey.ZeroString();
            return Task.FromResult(new Tuple<bool, string>(true, "Wallet login successful"));
        }
        catch (Exception ex)
        {
            _logger.Here().Error("{@Message}", ex.Message);
        }

        return Task.FromResult(new Tuple<bool, string>(false, "Unable to login"));
    }

    /// Initializes the wallet asynchronously.
    /// @param outputs The array of outputs.
    /// @return A task that represents the asynchronous operation. The task result contains a tuple with a boolean indicating if the wallet initialization was successful and a string message
    /// .
    /// /
    public Task<Tuple<bool, string>> InitializeWalletAsync(Output[] outputs)
    {
        Guard.Argument(outputs, nameof(outputs)).NotNull().NotEmpty();
        try
        {
            if (KeySet is null) return Task.FromResult(new Tuple<bool, string>(false, "Node wallet login required"));
            CacheTransactions.Clear();
            foreach (var vout in outputs) CacheTransactions.Add(vout.C, vout);
            const string pPoSMessageEnabled = "Pure Proof of Stake [ENABLED]";
            _logger.Information(pPoSMessageEnabled);
            return Task.FromResult(new Tuple<bool, string>(true,
                $"Node wallet received transactions. {pPoSMessageEnabled}"));
        }
        catch (Exception ex)
        {
            _logger.Here().Error("{@Message}", ex.Message);
        }

        return Task.FromResult(new Tuple<bool, string>(false, "Node wallet setup failed"));
    }

    /// <summary>
    /// Retrieves the safe guard blocks.
    /// </summary>
    /// <returns>A read-only list of Block objects representing the safe guard blocks.</returns>
    public IReadOnlyList<Block> GetSafeGuardBlocks()
    {
        lock (Locking)
        {
            return _readOnlySafeGuardBlocks;
        }
    }

    /// <summary>
    /// Creates a key set based on a key path, secret key, and chain code.
    /// </summary>
    /// <param name="keyPath">The key path to derive the keys.</param>
    /// <param name="secretKey">The secret key used for derivation.</param>
    /// <param name="chainCode">The chain code used for derivation.</param>
    /// <returns>A KeySet object containing the derived keys and necessary information.</returns>
    private KeySet CreateKeySet(KeyPath keyPath, byte[] secretKey, byte[] chainCode)
    {
        Guard.Argument(keyPath, nameof(keyPath)).NotNull();
        Guard.Argument(secretKey, nameof(secretKey)).NotNull().MaxCount(32);
        Guard.Argument(chainCode, nameof(chainCode)).NotNull().MaxCount(32);
        var masterKey = new ExtKey(new Key(secretKey), chainCode);
        var spendKey = masterKey.Derive(keyPath).PrivateKey;
        var scanKey = masterKey.Derive(keyPath = keyPath.Increment()).PrivateKey;
        return new KeySet
        {
            ChainCode = masterKey.ChainCode.ByteToHex(),
            KeyPath = keyPath.ToString(),
            RootKey = masterKey.PrivateKey.ToHex(),
            StealthAddress = spendKey.PubKey.CreateStealthAddress(scanKey.PubKey, _network).ToString()
        };
    }

    /// <summary>
    /// Creates an HD root key.
    /// </summary>
    /// <param name="seed">The seed used to generate the HD root key.</param>
    /// <param name="hdRoot">Output parameter to store the generated HD root key.</param>
    private static void CreateHdRootKey(SecureString seed, out ExtKey hdRoot)
    {
        Guard.Argument(seed, nameof(seed)).NotNull();
        Guard.Argument(seed, nameof(seed)).NotNull();
        var concatenateMnemonic = string.Join(" ", seed.FromSecureString());
        hdRoot = new Mnemonic(concatenateMnemonic).DeriveExtKey();
        concatenateMnemonic.ZeroString();
    }

    /// <summary>
    /// Handles the consumed cache items periodically to remove unused items.
    /// </summary>
    private void HandelConsumed()
    {
        _disposableHandelConsumed = Observable.Interval(TimeSpan.FromMilliseconds(10000))
            .Subscribe(_ =>
            {
                if (_applicationLifetime.ApplicationStopping.IsCancellationRequested) return;
                try
                {
                    var removeUnused = Helper.Util.GetUtcNow().AddSeconds(-30);
                    foreach (var consumed in CacheConsumed.GetItems())
                    {
                        if (consumed.Time < removeUnused)
                        {
                            CacheConsumed.Remove(consumed.Commit);
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.Error("{@}", ex.Message);
                }
            });
    }

    /// <summary>
    /// Handles the safeguard blocks by periodically fetching and updating the read-only safeguard blocks list.
    /// </summary>
    private void HandleSafeguardBlocks()
    {
        _disposableHandleSafeguardBlocks = Observable.Timer(TimeSpan.Zero, TimeSpan.FromMilliseconds(155520000))
            .Select(_ => Observable.FromAsync(async () =>
            {
                try
                {
                    if (_systemCore.ApplicationLifetime.ApplicationStopping.IsCancellationRequested) return;
                    var blocksResponse = await _systemCore.Graph().GetSafeguardBlocksAsync(new SafeguardBlocksRequest(147));
                    lock (Locking)
                    {
                        _readOnlySafeGuardBlocks = blocksResponse.Blocks;
                    }
                }
                catch (Exception)
                {
                    // Ignore
                }
            }))
            .Merge()
            .Subscribe();
    }

    /// <summary>
    /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
    /// </summary>
    /// <param name="disposing">A flag indicating whether to dispose of managed resources.</param>
    private void Dispose(bool disposing)
    {
        if (_disposed)
        {
            return;
        }

        if (disposing)
        {
            _disposableHandelConsumed?.Dispose();
            _disposableHandleSafeguardBlocks?.Dispose();
        }

        _disposed = true;
    }

    /// <summary>
    /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
    /// </summary>
    /// <remarks>
    /// Call <see cref="Dispose"/> when you are finished using the object. This method frees any resources that the object
    /// holds and marks the object as no longer needed.
    /// </remarks>
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }
}