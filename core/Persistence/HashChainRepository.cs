// Tangram by Matthew Hellyer is licensed under CC BY-NC-ND 4.0.
// To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using TangramXtgm.Extensions;
using Dawn;
using MessagePack;
using Serilog;
using TangramXtgm.Helper;
using TangramXtgm.Models;

namespace TangramXtgm.Persistence;

/// <summary>
/// Represents a repository for managing a hash chain of blocks.
/// </summary>
public interface IHashChainRepository : IRepository<Block>
{
    ValueTask<List<Block>> OrderByRangeAsync(Func<Block, ulong> selector, int skip, int take);
    new Task<bool> PutAsync(byte[] key, Block data);
    new bool Delete(byte[] key, byte[] hash);
    ulong Height { get; }
    ulong Count { get; }
}

/// <summary>
/// Represents a repository for storing and retrieving blocks in a hash chain.
/// Implements the IRepository interface for general repository functionality.
/// Implements the IHashChainRepository interface for specific hash chain repository functionality.
/// </summary>
public class HashChainRepository : Repository<Block>, IHashChainRepository
{
    private readonly ILogger _logger;
    private readonly IStoreDb _storeDb;
    private readonly ReaderWriterLockSlim _sync = new();

    /// <summary>
    /// Represents a repository for managing hash chain data using a database.
    /// </summary>
    /// <param name="storeDb">The database reference.</param>
    /// <param name="logger">The logger for logging events.</param>
    public HashChainRepository(IStoreDb storeDb, ILogger logger)
        : base(storeDb, logger)
    {
        _storeDb = storeDb;
        _logger = logger.ForContext("SourceContext", nameof(HashChainRepository));

        SetTableName(StoreDb.HashChainTable.ToString());

        AsyncHelper.Invoke(async () =>
        {
            Height = (ulong)await GetBlockHeightAsync();
            Count = (ulong)await CountAsync();
        });
    }

    /// <summary>
    /// The height property represents the height of an object.
    /// </summary>
    /// <value>
    /// An unsigned long integer representing the height of the object.
    /// </value>
    /// <remarks>
    /// This property has a private set that allows setting the height value only within the class it is defined.
    /// </remarks>
    public ulong Height { get; private set; }

    /// <summary>
    /// Gets the current count value.
    /// </summary>
    /// <value>
    /// The current count value.
    /// </value>
    public ulong Count { get; private set; }

    /// <summary>
    /// Stores a Block with the specified key in the database asynchronously.
    /// </summary>
    /// <param name="key">The key to associate with the Block.</param>
    /// <param name="data">The Block to store in the database.</param>
    /// <returns>A task that represents the asynchronous operation. The task result contains a value indicating whether the Block was successfully stored in the database (true) or not (false).</returns>
    public new Task<bool> PutAsync(byte[] key, Block data)
    {
        Guard.Argument(key, nameof(key)).NotNull().NotEmpty().MaxCount(64);
        Guard.Argument(data, nameof(data)).NotNull();
        if (data.Validate().Any()) return Task.FromResult(false);
        try
        {
            using (_sync.Write())
            {
                var cf = _storeDb.Rocks.GetColumnFamily(GetTableNameAsString());
                _storeDb.Rocks.Put(StoreDb.Key(GetTableNameAsString(), key),
                    MessagePackSerializer.Serialize(data), cf);
                Height = data.Height;
                Count++;
                return Task.FromResult(true);
            }
        }
        catch (Exception ex)
        {
            _logger.Here().Error(ex, "Error while storing in database");
        }

        return Task.FromResult(false);
    }

    /// <summary>
    /// Deletes a key-value pair from the database.
    /// </summary>
    /// <param name="key">The key of the data to delete.</param>
    /// <param name="hash">The hash of the data to delete.</param>
    /// <returns>True if the deletion is successful, false otherwise.</returns>
    public new bool Delete(byte[] key, byte[] hash)
    {
        Guard.Argument(key, nameof(key)).NotNull().NotEmpty().MaxCount(64);
        Guard.Argument(hash, nameof(hash)).NotNull().NotEmpty().MaxCount(32);
        try
        {
            using (_sync.Write())
            {
                var cf = _storeDb.Rocks.GetColumnFamily(GetTableNameAsString());
                _storeDb.Rocks.Remove(StoreDb.Key(GetTableNameAsString(), key), cf);
                Height--;
                Count--;
                return true;
            }
        }
        catch (Exception ex)
        {
            _logger.Here().Error(ex, "Error while removing from database");
        }

        return false;
    }

    /// <summary>
    /// Orders the blocks in the database by a specified range.
    /// </summary>
    /// <param name="selector">A function to extract a key from each block.</param>
    /// <param name="skip">The number of blocks to skip from the beginning of the ordered sequence.</param>
    /// <param name="take">The number of blocks to return in the ordered sequence.</param>
    /// <returns>A task that represents the asynchronous operation. The task result contains the ordered list of blocks.</returns>
    public ValueTask<List<Block>> OrderByRangeAsync(Func<Block, ulong> selector, int skip, int take)
    {
        Guard.Argument(selector, nameof(selector)).NotNull();
        Guard.Argument(skip, nameof(skip)).NotNegative();
        Guard.Argument(take, nameof(take)).NotNegative();
        try
        {
            using (_sync.Read())
            {
                var entries = IterateAsync().OrderBy(selector).Skip(skip).Take(take).ToListAsync();
                return entries;
            }
        }
        catch (Exception ex)
        {
            _logger.Here().Error(ex, "Error while reading database");
        }

        return default;
    }
}