// Tangram by Matthew Hellyer is licensed under CC BY-NC-ND 4.0.
// To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0

using System;
using System.Threading;
using System.Threading.Tasks;
using TangramXtgm.Extensions;
using Dawn;
using MessagePack;
using Serilog;
using TangramXtgm.Models;

namespace TangramXtgm.Persistence;

/// <summary>
/// Represents a repository for managing data protection information.
/// </summary>
public interface IDataProtectionRepository : IRepository<DataProtection>
{
    new Task<bool> PutAsync(byte[] key, DataProtection data);
}

/// <summary>
/// The DataProtectionRepository class is responsible for storing and retrieving DataProtection objects in a database.
/// </summary>
public class DataProtectionRepository : Repository<DataProtection>, IDataProtectionRepository
{
    private readonly ILogger _logger;
    private readonly IStoreDb _storeDb;
    private readonly ReaderWriterLockSlim _sync = new();

    /// <summary>
    /// Repository class for managing data protection.
    /// </summary>
    /// <param name="storeDb">The StoreDb instance.</param>
    /// <param name="logger">The ILogger instance.</param>
    public DataProtectionRepository(IStoreDb storeDb, ILogger logger)
        : base(storeDb, logger)
    {
        _storeDb = storeDb;
        _logger = logger;
        SetTableName(StoreDb.DataProtectionTable.ToString());
    }

    /// <summary>
    /// Stores data in the database with the specified key asynchronously.
    /// </summary>
    /// <param name="key">The key used to store the data.</param>
    /// <param name="data">The data to be stored.</param>
    /// <returns>A task representing the asynchronous operation. The task result indicates whether the data was successfully stored.</returns>
    public new Task<bool> PutAsync(byte[] key, DataProtection data)
    {
        Guard.Argument(key, nameof(key)).NotNull().NotEmpty().MaxCount(32);
        Guard.Argument(data, nameof(data)).NotNull();
        var saved = false;
        try
        {
            using (_sync.Write())
            {
                var cf = _storeDb.Rocks.GetColumnFamily(GetTableNameAsString());
                var buffer = MessagePackSerializer.Serialize(data);
                _storeDb.Rocks.Put(StoreDb.Key(GetTableNameAsString(), key), buffer, cf);
                saved = true;
            }
        }
        catch (Exception ex)
        {
            _logger.Here().Error(ex, "Error while storing in database");
        }

        return Task.FromResult(saved);
    }
}