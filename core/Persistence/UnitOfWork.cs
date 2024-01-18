// Tangram by Matthew Hellyer is licensed under CC BY-NC-ND 4.0.
// To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0

using System;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Serilog;

namespace TangramXtgm.Persistence;

/// <summary>
/// Represents a unit of work for performing various operations on repositories.
/// </summary>
public interface IUnitOfWork
{
    IStoreDb StoreDb { get; }
    IXmlRepository DataProtectionKeys { get; }
    IDataProtectionRepository DataProtectionPayload { get; }
    IHashChainRepository HashChainRepository { get; }
    void Dispose();
}

/// <summary>
/// Implements the Unit of Work pattern by providing a way to manage transactions and coordinate the work of multiple repositories.
/// </summary>
public class UnitOfWork : IUnitOfWork, IDisposable
{
    /// <summary>
    /// Represents a unit of work for performing database operations.
    /// </summary>
    /// <param name="folderDb">The folder path of the database.</param>
    /// <param name="logger">The logger instance for logging messages.</param>
    public UnitOfWork(string folderDb, ILogger logger)
    {
        StoreDb = new StoreDb(folderDb);
        var log = logger.ForContext("SourceContext", nameof(UnitOfWork));
        DataProtectionPayload = new DataProtectionRepository(StoreDb, log);
        HashChainRepository = new HashChainRepository(StoreDb, log);
    }

    /// <summary>
    /// Represents a property that provides access to an instance of the StoreDb class.
    /// </summary>
    /// <value>
    /// An instance of the StoreDb class.
    /// </value>
    public IStoreDb StoreDb { get; }

    /// <summary>
    /// Gets the repository for storing data protection keys.
    /// </summary>
    /// <remarks>
    /// This repository is used by the Data Protection middleware to store and retrieve keys for the purpose of encrypting and decrypting sensitive data.
    /// </remarks>
    public IXmlRepository DataProtectionKeys { get; }

    /// <summary>
    /// Represents the data protection payload used by the application.
    /// </summary>
    public IDataProtectionRepository DataProtectionPayload { get; }

    /// <summary>
    /// Represents a repository for storing and retrieving hash chains.
    /// </summary>
    public IHashChainRepository HashChainRepository { get; }

    /// <summary>
    /// Disposes the resources used by the StoreDb.
    /// </summary>
    public void Dispose()
    {
        StoreDb.Rocks.Dispose();
    }
}