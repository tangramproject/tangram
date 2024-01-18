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
using Microsoft.IO;
using RocksDbSharp;
using Serilog;
using TangramXtgm.Helper;

namespace TangramXtgm.Persistence;

/// <summary>
/// Represents a generic repository interface for data access.
/// </summary>
/// <typeparam name="T">The type of data stored in the repository.</typeparam>
public interface IRepository<T>
{
    Task<long> CountAsync();
    Task<long> GetBlockHeightAsync();
    Task<T> GetAsync(byte[] key);
    Task<T> GetAsync(Func<T, ValueTask<bool>> expression);
    void SetTableName(string tableName);
    string GetTableNameAsString();
    byte[] GetTableNameAsBytes();
    Task<bool> PutAsync(byte[] key, T data);
    Task<IList<T>> RangeAsync(long skip, int take);
    Task<T> LastAsync();
    ValueTask<List<T>> WhereAsync(Func<T, ValueTask<bool>> expression);
    Task<T> FirstAsync();
    ValueTask<List<T>> SelectAsync(Func<T, ValueTask<T>> selector);
    ValueTask<List<T>> SkipAsync(int skip);
    ValueTask<List<T>> TakeAsync(int take);
    bool Delete(byte[] key);
    Task<IList<T>> TakeLongAsync(ulong take);
    IAsyncEnumerable<T> IterateAsync();
}

/// <summary>
/// Generic repository class for CRUD operations on a database table
/// </summary>
/// <typeparam name="T">The type of objects stored in the repository</typeparam>
public class Repository<T> : IRepository<T> where T : class, new()
{
    private readonly ILogger _logger;
    private readonly ReadOptions _readOptions;
    private readonly IStoreDb _storeDb;
    private readonly ReaderWriterLockSlim _sync = new();

    private string _tableName;
    private byte[] _tableNameBytes;

    /// <summary>
    /// Repository class for accessing data from the store database.
    /// </summary>
    /// <typeparam name="T">The type of data stored in the database.</typeparam>
    protected Repository(IStoreDb storeDb, ILogger logger)
    {
        _storeDb = storeDb;
        _logger = logger.ForContext("SourceContext", nameof(Repository<T>));

        _readOptions = new ReadOptions();
        _readOptions
            .SetPrefixSameAsStart(true)
            .SetVerifyChecksums(false);
    }

    /// <summary>
    /// Retrieves the current block height asynchronously.
    /// </summary>
    /// <returns>
    /// A <see cref="Task{TResult}"/> representing the asynchronous operation.
    /// The task result contains the current block height.
    /// </returns>
    public async Task<long> GetBlockHeightAsync()
    {
        var height = await CountAsync() - 1;
        if (height < 0) height = 0;
        return height;
    }

    /// <summary>
    /// Retrieves the count of records in the database asynchronously.
    /// </summary>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation. The task result contains the count of records.</returns>
    public Task<long> CountAsync()
    {
        long count = 0;
        try
        {
            using (_sync.Read())
            {
                var cf = _storeDb.Rocks.GetColumnFamily(_tableName);
                using var iterator = _storeDb.Rocks.NewIterator(cf, _readOptions);
                unsafe
                {
                    fixed (byte* k = _tableNameBytes.AsSpan())
                    {
                        for (iterator.Seek(k, (ulong)_tableNameBytes.Length); iterator.Valid(); iterator.Next())
                        {
                            Interlocked.Increment(ref count);
                        }
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.Here().Error(ex, "Error while reading database");
        }

        return Task.FromResult(count);
    }

    /// <summary>
    /// Retrieves an object of type T asynchronously from the database using the specified key.
    /// </summary>
    /// <param name="key">The key used to retrieve the object from the database.</param>
    /// <returns>An object of type T if found; otherwise, null.</returns>
    public async Task<T> GetAsync(byte[] key)
    {
        Guard.Argument(key, nameof(key)).NotNull().NotEmpty();
        try
        {
            using (_sync.Read())
            {
                var cf = _storeDb.Rocks.GetColumnFamily(_tableName);
                var value = _storeDb.Rocks.Get(StoreDb.Key(_tableName, key), cf, _readOptions);
                if (value is { })
                {
                    await using var stream = Util.Manager.GetStream(value.AsSpan()) as RecyclableMemoryStream;
                    var entry = await MessagePackSerializer.DeserializeAsync<T>(stream);
                    return entry;
                }
            }
        }
        catch (Exception ex)
        {
            _logger.Here().Error(ex, "Error while reading database");
        }

        return null;
    }

    /// <summary>
    /// Asynchronously retrieves the first element that satisfies the provided condition.
    /// </summary>
    /// <param name="expression">A function that determines whether an element meets the condition.</param>
    /// <returns>The first element that satisfies the provided condition, or null if no such element is found or an error occurs while reading the database.</returns>
    public async Task<T> GetAsync(Func<T, ValueTask<bool>> expression)
    {
        Guard.Argument(expression, nameof(expression)).NotNull();
        try
        {
            using (_sync.Read())
            {
                var first = IterateAsync().FirstOrDefaultAwaitAsync(expression);
                if (first.IsCompleted)
                {
                    var entry = await first;
                    return entry;
                }
            }
        }
        catch (Exception ex)
        {
            _logger.Here().Error(ex, "Error while reading database");
        }

        return null;
    }

    /// <summary>
    /// Deletes a record from the database using the specified key.
    /// </summary>
    /// <param name="key">The key of the record to delete.</param>
    /// <returns>True if the record is successfully deleted; otherwise, false.</returns>
    public bool Delete(byte[] key)
    {
        Guard.Argument(key, nameof(key)).NotNull().NotEmpty();
        try
        {
            using (_sync.Write())
            {
                var cf = _storeDb.Rocks.GetColumnFamily(_tableName);
                _storeDb.Rocks.Remove(StoreDb.Key(_tableName, key), cf);
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
    /// Retrieves and returns the first element from the database.
    /// </summary>
    /// <typeparam name="T">The type of the element to retrieve.</typeparam>
    /// <returns>The first element from the database, or null if no elements are found.</returns>
    public async Task<T> FirstAsync()
    {
        try
        {
            using (_sync.Read())
            {
                var cf = _storeDb.Rocks.GetColumnFamily(_tableName);
                using var iterator = _storeDb.Rocks.NewIterator(cf, _readOptions);
                iterator.SeekToFirst();
                if (iterator.Valid())
                {
                    await using var stream = Util.Manager.GetStream(iterator.Value().AsSpan()) as RecyclableMemoryStream;
                    var entry = await MessagePackSerializer.DeserializeAsync<T>(stream);
                    return entry;
                }
            }
        }
        catch (Exception ex)
        {
            _logger.Here().Error(ex, "Error while reading database");
        }

        return null;
    }

    /// <summary>
    /// Stores the specified data using the provided key asynchronously.
    /// </summary>
    /// <typeparam name="T">The type of data to store.</typeparam>
    /// <param name="key">The key to use for storing the data.</param>
    /// <param name="data">The data to store.</param>
    /// <returns>A task that represents the asynchronous operation.
    /// The task result contains a boolean value indicating whether the data was stored successfully.</returns>
    public Task<bool> PutAsync(byte[] key, T data)
    {
        Guard.Argument(key, nameof(key)).NotNull().NotEmpty();
        Guard.Argument(data, nameof(data)).NotNull();
        try
        {
            using (_sync.Write())
            {
                var cf = _storeDb.Rocks.GetColumnFamily(_tableName);
                var buffer = MessagePackSerializer.Serialize(data);
                _storeDb.Rocks.Put(StoreDb.Key(_tableName, key), buffer, cf);
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
    /// Sets the name of the table.
    /// </summary>
    /// <param name="tableName">The name of the table.</param>
    public void SetTableName(string tableName)
    {
        Guard.Argument(tableName, nameof(tableName)).NotNull().NotEmpty().NotWhiteSpace();
        using (_sync.Write())
        {
            _tableName = tableName;
            _tableNameBytes = tableName.ToBytes();
        }
    }

    /// <summary>
    /// Retrieves the name of the table as a string.
    /// </summary>
    /// <returns>The name of the table.</returns>
    public string GetTableNameAsString()
    {
        using (_sync.Read())
        {
            return _tableName;
        }
    }

    /// <summary>
    /// Gets the table name as a byte array.
    /// </summary>
    /// <returns>The table name as a byte array.</returns>
    public byte[] GetTableNameAsBytes()
    {
        using (_sync.Read())
        {
            return _tableNameBytes;
        }
    }

    /// <summary>
    /// Retrieves a range of items asynchronously from the database.
    /// </summary>
    /// <param name="skip">The number of items to skip before starting to retrieve items.</param>
    /// <param name="take">The maximum number of items to retrieve.</param>
    /// <returns>An asynchronous task that returns a list of items.</returns>
    public async Task<IList<T>> RangeAsync(long skip, int take)
    {
        Guard.Argument(skip, nameof(skip)).Negative();
        Guard.Argument(take, nameof(take)).Negative();
        IList<T> entries = new List<T>(take);
        try
        {
            using (_sync.Read())
            {
                long iSkip = 0;
                var iTake = 0;
                var cf = _storeDb.Rocks.GetColumnFamily(_tableName);
                using var iterator = _storeDb.Rocks.NewIterator(cf, _readOptions);
                for (iterator.SeekToFirst(); iterator.Valid(); iterator.Next())
                {
                    iSkip++;
                    if (skip != 0)
                        if (iSkip % skip != 0)
                            continue;
                    await using var stream = Util.Manager.GetStream(iterator.Value().AsSpan()) as RecyclableMemoryStream;
                    entries.Add(await MessagePackSerializer.DeserializeAsync<T>(stream));
                    iTake++;
                    if (iTake % take == 0) break;
                }
            }
        }
        catch (Exception ex)
        {
            _logger.Here().Error(ex, "Error while reading database");
        }

        return entries;
    }

    /// <summary>
    /// Retrieves the last entry in the database asynchronously.
    /// </summary>
    /// <typeparam name="T">The type of the entry.</typeparam>
    /// <returns>The last entry in the database as an instance of <typeparamref name="T"/> if it exists; otherwise, <see langword="null"/>.</returns>
    public async Task<T> LastAsync()
    {
        try
        {
            using (_sync.Read())
            {
                var cf = _storeDb.Rocks.GetColumnFamily(_tableName);
                using var iterator = _storeDb.Rocks.NewIterator(cf, _readOptions);
                iterator.SeekToLast();
                if (iterator.Valid())
                {
                    await using var stream = Util.Manager.GetStream(iterator.Value().AsSpan()) as RecyclableMemoryStream;
                    var entry = await MessagePackSerializer.DeserializeAsync<T>(stream);
                    return entry;
                }
            }
        }
        catch (Exception ex)
        {
            _logger.Here().Error(ex, "Error while reading database");
        }

        return null;
    }

    /// <summary>
    /// Filters the elements of the collection asynchronously based on a specified condition.
    /// </summary>
    /// <param name="expression">The expression to test each element against.</param>
    /// <returns>A task that represents the asynchronous operation. The task result contains a list of elements from the collection that satisfy the specified condition.</returns>
    public ValueTask<List<T>> WhereAsync(Func<T, ValueTask<bool>> expression)
    {
        Guard.Argument(expression, nameof(expression)).NotNull();
        try
        {
            using (_sync.Read())
            {
                var entries = IterateAsync().WhereAwait(expression).ToListAsync();
                return entries;
            }
        }
        catch (Exception ex)
        {
            _logger.Here().Error(ex, "Error while reading database");
        }

        return default;
    }

    /// <summary>
    /// Selects items from the database asynchronously based on the specified selector function.
    /// </summary>
    /// <param name="selector">A function that specifies the transformation to be applied to each item.</param>
    /// <returns>A <see cref="ValueTask{TResult}"/> representing the asynchronous operation that returns a list of selected items.</returns>
    public ValueTask<List<T>> SelectAsync(Func<T, ValueTask<T>> selector)
    {
        Guard.Argument(selector, nameof(selector)).NotNull();
        try
        {
            using (_sync.Read())
            {
                var entries = IterateAsync().SelectAwait(selector).ToListAsync();
                return entries;
            }
        }
        catch (Exception ex)
        {
            _logger.Here().Error(ex, "Error while reading database");
        }

        return default;
    }

    /// <summary>
    /// Skips a specified number of elements from the beginning of the collection asynchronously.
    /// </summary>
    /// <param name="skip">The number of elements to skip.</param>
    /// <returns>A <see cref="ValueTask{TResult}"/> that represents the asynchronous operation. The task result contains a list of elements.</returns>
    public ValueTask<List<T>> SkipAsync(int skip)
    {
        Guard.Argument(skip, nameof(skip)).NotNegative();
        try
        {
            using (_sync.Read())
            {
                var entries = IterateAsync().Skip(skip).ToListAsync();
                return entries;
            }
        }
        catch (Exception ex)
        {
            _logger.Here().Error(ex, "Error while reading database");
        }

        return default;
    }

    /// <summary>
    /// Takes a specified number of items asynchronously.
    /// </summary>
    /// <param name="take">The number of items to take.</param>
    /// <returns>A <see cref="ValueTask{List{T}}"/> representing the asynchronous operation of taking the items.</returns>
    public ValueTask<List<T>> TakeAsync(int take)
    {
        Guard.Argument(take, nameof(take)).NotNegative();
        try
        {
            using (_sync.Read())
            {
                var entries = IterateAsync().Take(take).ToListAsync();
                return entries;
            }
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Error while reading database");
        }

        return default;
    }

    /// <summary>
    /// Retrieves a specified number of items asynchronously from the database.
    /// </summary>
    /// <typeparam name="T">The type of items to retrieve</typeparam>
    /// <param name="take">The number of items to retrieve</param>
    /// <returns>A task representing the asynchronous operation. The task result contains a list of retrieved items.</returns>
    public async Task<IList<T>> TakeLongAsync(ulong take)
    {
        Guard.Argument(take, nameof(take)).NotNegative();
        IList<T> entries = new List<T>();
        try
        {
            using (_sync.Read())
            {
                take = take == 0 ? 1 : take;
                ulong iTake = 0;
                var cf = _storeDb.Rocks.GetColumnFamily(_tableName);
                using var iterator = _storeDb.Rocks.NewIterator(cf, _readOptions);
                for (iterator.SeekToFirst(); iterator.Valid(); iterator.Next())
                {
                    await using var stream = Util.Manager.GetStream(iterator.Value().AsSpan()) as RecyclableMemoryStream;
                    entries.Add(await MessagePackSerializer.DeserializeAsync<T>(stream));
                    iTake++;
                    if (iTake % take == 0) break;
                }
            }
        }
        catch (Exception ex)
        {
            _logger.Here().Error(ex, "Error while reading database");
        }

        return entries;
    }

    /// <summary>
    /// Asynchronously iterates through the database entries and returns them one by one.
    /// </summary>
    /// <typeparam name="T">The type of the entries.</typeparam>
    /// <returns>An asynchronous enumerable of entries of type T.</returns>
#pragma warning disable 1998
    public async IAsyncEnumerable<T> IterateAsync()
#pragma warning restore 1998
    {
        var cf = _storeDb.Rocks.GetColumnFamily(_tableName);
        using var iterator = _storeDb.Rocks.NewIterator(cf, _readOptions);
        for (iterator.Seek(_tableNameBytes); iterator.Valid(); iterator.Next())
        {
            if (!iterator.Valid()) continue;
            await using var stream = Util.Manager.GetStream(iterator.Value().AsSpan()) as RecyclableMemoryStream;
            yield return await MessagePackSerializer.DeserializeAsync<T>(stream);
        }
    }
}