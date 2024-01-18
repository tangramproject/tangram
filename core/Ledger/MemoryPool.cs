// Tangram by Matthew Hellyer is licensed under CC BY-NC-ND 4.0.
// To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0

using System;
using System.Collections.Generic;
using System.Linq;
using System.Reactive.Linq;
using System.Threading.Tasks;
using TangramXtgm.Extensions;
using Dawn;
using MessagePack;
using NBitcoin;
using Serilog;
using TangramXtgm.Helper;
using TangramXtgm.Models;
using TangramXtgm.Persistence;
using Transaction = TangramXtgm.Models.Transaction;

namespace TangramXtgm.Ledger;

/// <summary>
/// Represents a memory pool that stores and manages transactions.
/// </summary>
public interface IMemoryPool
{
    Task<VerifyResult> NewTransactionAsync(Transaction transaction);
    Transaction Get(in byte[] hash);
    Transaction[] GetMany();
    Task<Transaction[]> GetVerifiedTransactionsAsync(int take);
    int Count();
}

/// <summary>
/// Represents a memory pool for storing and managing transactions.
/// </summary>
public class MemoryPool : IMemoryPool, IDisposable
{
    private readonly ISystemCore _systemCore;
    private readonly ILogger _logger;
    private readonly Caching<string> _syncCacheSeenTransactions = new();
    private readonly Caching<Transaction> _syncCacheTransactions = new();
    private IDisposable _disposableHandelSeenTransactions;
    private bool _disposed;

    /// <summary>
    /// </summary>
    /// <param name="systemCore"></param>
    /// <param name="logger"></param>
    public MemoryPool(ISystemCore systemCore, ILogger logger)
    {
        _systemCore = systemCore;
        _logger = logger.ForContext("SourceContext", nameof(MemoryPool));
        Init();
    }

    /// <summary>
    /// Creates a new transaction asynchronously and broadcasts it.
    /// </summary>
    /// <param name="transaction">The transaction to be created.</param>
    /// <returns>A task representing the asynchronous operation. The task result is a VerifyResult indicating the success or failure of the transaction creation.</returns>
    public async Task<VerifyResult> NewTransactionAsync(Transaction transaction)
    {
        Guard.Argument(transaction, nameof(transaction)).NotNull();
        try
        {
            if (transaction.OutputType() == CoinType.Coinstake)
            {
                _logger.Fatal("Blocked coinstake transaction with {@TxId}", transaction.TxnId.ByteToHex());
                return VerifyResult.Invalid;
            }

            if (transaction.HasErrors().Any()) return VerifyResult.Invalid;
            if (!_syncCacheSeenTransactions.Contains(transaction.TxnId))
            {
                _syncCacheTransactions.Add(transaction.TxnId, transaction);
                _syncCacheSeenTransactions.Add(transaction.TxnId, transaction.TxnId.ByteToHex());
                await _systemCore.Broadcast().PostAsync((TopicType.AddTransaction, MessagePackSerializer.Serialize(transaction)));
            }
        }
        catch (Exception ex)
        {
            _logger.Here().Error("{@Message}", ex.Message);
            return VerifyResult.Invalid;
        }

        return VerifyResult.Succeed;
    }

    /// <summary>
    /// Retrieves a transaction by its ID.
    /// </summary>
    /// <param name="transactionId">The ID of the transaction to retrieve.</param>
    /// <returns>The retrieved Transaction object, or null if the transaction is not found.</returns>
    public Transaction Get(in byte[] transactionId)
    {
        Guard.Argument(transactionId, nameof(transactionId)).NotNull().NotEmpty().MaxCount(32);
        try
        {
            if (_syncCacheTransactions.TryGet(transactionId, out var transaction))
                return transaction;
        }
        catch (Exception ex)
        {
            _logger.Here().Error(ex, "Unable to find transaction with {@TxId}", transactionId.ByteToHex());
        }

        return null;
    }

    /// <summary>
    /// Retrieves multiple transactions from the sync cache.
    /// </summary>
    /// <returns>An array of Transaction objects.</returns>
    public Transaction[] GetMany()
    {
        return _syncCacheTransactions.GetItems();
    }

    /// <summary>
    /// Retrieves verified transactions asynchronously.
    /// </summary>
    /// <param name="take">The number of transactions to retrieve.</param>
    /// <returns>An array of verified transactions.</returns>
    public async Task<Transaction[]> GetVerifiedTransactionsAsync(int take)
    {
        Guard.Argument(take, nameof(take)).NotNegative();
        var validTransactions = new List<Transaction>();
        var validator = _systemCore.Validator();
        foreach (var transaction in _syncCacheTransactions.GetItems().Take(take).Select(x => x)
                     .OrderByDescending(x => x.Vtime.I))
        {
            var verifyTransaction = await validator.VerifyTransactionAsync(transaction);
            if (verifyTransaction == VerifyResult.Succeed) validTransactions.Add(transaction);

            _syncCacheTransactions.Remove(transaction.TxnId);
        }

        return validTransactions.ToArray();
    }

    /// <summary>
    /// </summary>
    /// <returns></returns>
    public int Count()
    {
        return _syncCacheTransactions.Count;
    }

    /// <summary>
    /// Initializes the object.
    /// </summary>
    private void Init()
    {
        HandelSeenTransactions();
    }

    /// <summary>
    /// Handles seen transactions in the system by removing transactions from sync cache and seen transactions cache that are older than one hour.
    /// </summary>
    private void HandelSeenTransactions()
    {
        _disposableHandelSeenTransactions = Observable.Interval(TimeSpan.FromHours(1))
            .Subscribe(_ =>
            {
                if (_systemCore.ApplicationLifetime.ApplicationStopping.IsCancellationRequested) return;
                try
                {
                    var removeTransactionsBeforeTimestamp = Util.GetUtcNow().AddHours(-1).ToUnixTimestamp();
                    var syncCacheTransactions = _syncCacheTransactions.GetItems()
                        .Where(x => x.Vtime.L < removeTransactionsBeforeTimestamp);
                    foreach (var transaction in syncCacheTransactions)
                    {
                        _syncCacheTransactions.Remove(transaction.TxnId);
                        _syncCacheSeenTransactions.Remove(transaction.TxnId);
                    }
                }
                catch (TaskCanceledException)
                {
                    // Ignore
                }
                catch (Exception ex)
                {
                    _logger.Here().Error("{@Message}", ex.Message);
                }
            });
    }

    /// <summary>
    /// Releases all resources used by the current instance.
    /// </summary>
    /// <param name="disposing">A boolean value indicating if the method is being called from the Dispose method.</param>
    private void Dispose(bool disposing)
    {
        if (_disposed)
        {
            return;
        }

        if (disposing)
        {
            _disposableHandelSeenTransactions?.Dispose();
        }

        _disposed = true;
    }

    /// <summary>
    /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
    /// </summary>
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }
}