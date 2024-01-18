// Tangram by Matthew Hellyer is licensed under CC BY-NC-ND 4.0.
// To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0

using System;
using System.IO;
using TangramXtgm.Extensions;
using RocksDbSharp;

namespace TangramXtgm.Persistence;

/// <summary>
/// This interface represents a store database, which provides access to a RocksDb instance.
/// </summary>
public interface IStoreDb
{
    RocksDb Rocks { get; }
}

/// <summary>
/// Represents a database used for storing data.
/// </summary>
public sealed class StoreDb : IStoreDb, IDisposable
{
    public static readonly StoreDb DataProtectionTable = new(1, "DataProtectionTable");
    public static readonly StoreDb HashChainTable = new(2, "HashChainTable");
    public static readonly StoreDb TransactionOutputTable = new(3, "TransactionOutputTable");
    public static readonly StoreDb OrphanBlockTable = new(4, "OrphanBlockTable");

    private readonly string _name;
    private readonly byte[] _nameBytes;
    private readonly int _value;

    private bool _disposedValue;

    /// <summary>
    /// Initializes a new instance of the StoreDb class with the specified value and name.
    /// </summary>
    /// <param name="value">The value of the StoreDb object.</param>
    /// <param name="name">The name of the StoreDb object.</param>
    private StoreDb(int value, string name)
    {
        _value = value;
        _name = name;
        _nameBytes = name.ToBytes();
    }

    /// <summary>
    /// The StoreDb class is responsible for initializing and managing a RocksDB database. </summary> <param name="folder">The name of the folder where the database files will be stored.</param>
    /// /
    public StoreDb(string folder)
    {
        try
        {
            var dataPath =
                Path.Combine(
                    Path.GetDirectoryName(AppDomain.CurrentDomain.BaseDirectory) ??
                    throw new InvalidOperationException(), folder);

            var blockBasedTableOptions = BlockBasedTableOptions();
            var columnFamilies = ColumnFamilies(blockBasedTableOptions);
            var options = DbOptions();

            Rocks = RocksDb.Open(options, dataPath, columnFamilies);
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            throw;
        }
    }

    /// <summary>
    /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
    /// </summary>
    public void Dispose()
    {
        Dispose(true);
    }

    /// <summary>
    /// Gets the Rocks database.
    /// </summary>
    /// <value>
    /// The Rocks database.
    /// </value>
    public RocksDb Rocks { get; }

    /// <summary>
    /// Generates a new byte array by combining the specified table and key.
    /// </summary>
    /// <param name="table">The table string.</param>
    /// <param name="key">The key byte array.</param>
    /// <returns>A new byte array created by combining the table and key.</returns>
    public static byte[] Key(string table, byte[] key)
    {
        Span<byte> dbKey = stackalloc byte[key.Length + table.Length];
        for (var i = 0; i < table.Length; i++) dbKey[i] = (byte)table[i];
        key.AsSpan().CopyTo(dbKey[table.Length..]);
        return dbKey.ToArray();
    }

    /// <summary>
    /// Creates a collection of column families using the provided BlockBasedTableOptions.
    /// </summary>
    /// <param name="blockBasedTableOptions">The BlockBasedTableOptions to be used for column families.</param>
    /// <returns>A collection of column families.</returns>
    private static ColumnFamilies ColumnFamilies(BlockBasedTableOptions blockBasedTableOptions)
    {
        var columnFamilies = new ColumnFamilies
        {
            { "default", new ColumnFamilyOptions().OptimizeForPointLookup(256) },
            { DataProtectionTable.ToString(), ColumnFamilyOptions(blockBasedTableOptions) },
            { HashChainTable.ToString(), ColumnFamilyOptions(blockBasedTableOptions) },
            { TransactionOutputTable.ToString(), ColumnFamilyOptions(blockBasedTableOptions) },
            { OrphanBlockTable.ToString(), ColumnFamilyOptions(blockBasedTableOptions) }
        };
        return columnFamilies;
    }

    /// <summary>
    /// Creates an instance of DbOptions with default values and customization.
    /// </summary>
    /// <returns>Returns an instance of DbOptions with default values and customization.</returns>
    private static DbOptions DbOptions()
    {
        var options = new DbOptions()
            .EnableStatistics()
            .SetCreateMissingColumnFamilies()
            .SetCreateIfMissing()
            .SetMaxBackgroundFlushes(2)
            .SetMaxBackgroundCompactions(Environment.ProcessorCount)
            .SetKeepLogFileNum(1)
            .SetDeleteObsoleteFilesPeriodMicros(21600000000)
            .SetManifestPreallocationSize(4194304)
            .SetMaxManifestFileSize(1073741824)
            .SetWalRecoveryMode(Recovery.PointInTime)
            .SetMaxOpenFiles(-1)
            .SetEnableWriteThreadAdaptiveYield(true)
            .SetAllowConcurrentMemtableWrite(true)
            .SetMaxBackgroundCompactions(-1)
            .SetStatsDumpPeriodSec(100)
            .SetParanoidChecks();
        return options;
    }

    /// <summary>
    /// Creates a <see cref="ColumnFamilyOptions"/> object with the specified <see cref="BlockBasedTableOptions"/>.
    /// </summary>
    /// <param name="blockBasedTableOptions">The options for the block-based table.</param>
    /// <returns>A new <see cref="ColumnFamilyOptions"/> object.</returns>
    private static ColumnFamilyOptions ColumnFamilyOptions(BlockBasedTableOptions blockBasedTableOptions)
    {
        var columnFamilyOptions = new ColumnFamilyOptions()
            .SetMemtableHugePageSize(2 * 1024 * 1024)
            .SetPrefixExtractor(SliceTransform.CreateFixedPrefix(8))
            .SetBlockBasedTableFactory(blockBasedTableOptions)
            .SetWriteBufferSize(64 * 1024 * 1024)
            .SetTargetFileSizeBase(64 * 1024 * 1024)
            .SetMaxBytesForLevelBase(512 * 1024 * 1024)
            .SetCompactionStyle(Compaction.Level)
            .SetLevel0FileNumCompactionTrigger(8)
            .SetLevel0SlowdownWritesTrigger(17)
            .SetLevel0StopWritesTrigger(24)
            .SetMaxWriteBufferNumber(3)
            .SetMaxBytesForLevelMultiplier(8)
            .SetNumLevels(4);
        return columnFamilyOptions;
    }

    /// <summary>
    /// Creates a new instance of BlockBasedTableOptions.
    /// </summary>
    /// <returns>A new instance of BlockBasedTableOptions with the specified options set.</returns>
    private static BlockBasedTableOptions BlockBasedTableOptions()
    {
        var blockBasedTableOptions = new BlockBasedTableOptions()
            .SetFilterPolicy(BloomFilterPolicy.Create(10, false))
            .SetWholeKeyFiltering(false)
            .SetFormatVersion(4)
            .SetIndexType(BlockBasedTableIndexType.Hash)
            .SetBlockSize(16 * 1024)
            .SetCacheIndexAndFilterBlocks(true)
            .SetBlockCache(Cache.CreateLru(32 * 1024 * 1024))
            .SetPinL0FilterAndIndexBlocksInCache(true);
        return blockBasedTableOptions;
    }

    /// <summary>
    /// Disposes the resources used by the current object.
    /// </summary>
    /// <param name="disposing">
    /// Determines whether the method is being called from the Dispose() method or the finalizer.
    /// </param>
    private void Dispose(bool disposing)
    {
        if (_disposedValue) return;
        if (disposing) Rocks?.Dispose();

        _disposedValue = true;
    }

    /// <summary>
    /// Converts the object to an integer value.
    /// </summary>
    /// <returns>The integer value of the object.</returns>
    public int ToValue()
    {
        return _value;
    }

    /// <summary>
    /// Converts the name to a byte array.
    /// </summary>
    /// <returns>The byte array representing the name.</returns>
    public byte[] ToBytes()
    {
        return _nameBytes;
    }

    /// <summary>
    /// Returns a string representation of the current object.
    /// </summary>
    /// <returns>A string that represents the current object.</returns>
    public override string ToString()
    {
        return _name;
    }
}