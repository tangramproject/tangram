// Tangram by Matthew Hellyer is licensed under CC BY-NC-ND 4.0.
// To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Dawn;
using RocksDbSharp;

namespace TangramXtgm.Persistence;

/// <summary>
/// Class for caching items.
/// </summary>
/// <typeparam name="TItem">The type of items to be cached.</typeparam>
public class Caching<TItem>
{
    private readonly Dictionary<byte[], TItem> _innerDictionary = new(BinaryComparer.Default);
    private readonly ReaderWriterLockSlim _rwLock = new(LockRecursionPolicy.SupportsRecursion);

    /// <summary>
    /// Gets or sets the value associated with the specified key in the dictionary.
    /// </summary>
    /// <typeparam name="TItem">The type of the item in the dictionary.</typeparam>
    /// <param name="key">The key of the item to get or set.</param>
    /// <returns>The value associated with the specified key, or the default value of the type if the key does not exist.</returns>
    public TItem this[byte[] key]
    {
        get
        {
            _rwLock.EnterReadLock();
            try
            {
                return _innerDictionary[key];
            }
            catch (Exception)
            {
                return default;
            }
            finally
            {
                _rwLock.ExitReadLock();
            }
        }
    }

    /// <summary>
    /// Gets the number of elements contained in the dictionary.
    /// </summary>
    /// <returns>
    /// The number of elements contained in the dictionary.
    /// </returns>
    public int Count
    {
        get
        {
            _rwLock.EnterReadLock();
            try
            {
                return _innerDictionary.Count;
            }
            finally
            {
                _rwLock.ExitReadLock();
            }

        }
    }

    /// <summary>
    /// Adds an item with the specified key to the dictionary.
    /// </summary>
    /// <param name="key">The key of the item.</param>
    /// <param name="item">The item to add.</param>
    public void Add(byte[] key, TItem item)
    {
        _rwLock.EnterWriteLock();
        try
        {
            if (!_innerDictionary.TryGetValue(key, out _)) _innerDictionary.Add(key, item);
        }
        finally
        {
            _rwLock.ExitWriteLock();
        }
    }

    /// <summary>
    /// Adds or updates an item in the dictionary.
    /// </summary>
    /// <param name="key">The key of the item.</param>
    /// <param name="item">The item to be added or updated.</param>
    /// <returns>
    /// <c>true</c> if the item was added or updated; otherwise, <c>false</c>.
    /// </returns>
    public bool AddOrUpdate(byte[] key, TItem item)
    {
        _rwLock.EnterWriteLock();
        try
        {
            if (_innerDictionary.TryGetValue(key, out _))
            {
                _innerDictionary[key] = item;
                return true;
            }
            else
            {
                _innerDictionary.Add(key, item);
                return true;
            }
        }
        finally
        {
            _rwLock.ExitWriteLock();
        }
    }

    /// <summary>
    /// Removes an item from the dictionary with the specified key.
    /// </summary>
    /// <param name="key">The key of the item to remove.</param>
    /// <returns>True if the item was found and removed; otherwise, false.</returns>
    public bool Remove(byte[] key)
    {
        _rwLock.EnterWriteLock();
        try
        {
            if (_innerDictionary.TryGetValue(key, out var cachedItem))
            {
                _innerDictionary.Remove(key);
                if (cachedItem is IDisposable disposable)
                {
                    disposable.Dispose();
                }
                return true;
            }
        }
        finally
        {
            _rwLock.ExitWriteLock();
        }

        return false;
    }

    /// <summary>
    /// Tries to get the value associated with the specified key from the inner dictionary.
    /// </summary>
    /// <param name="key">The key of the value to retrieve.</param>
    /// <param name="item">When this method returns, contains the value associated with the specified key if the key is found, otherwise contains the default value.</param>
    /// <returns>true if the inner dictionary contains an element with the specified key; otherwise, false.</returns>
    public bool TryGet(byte[] key, out TItem item)
    {
        _rwLock.EnterReadLock();
        try
        {
            if (_innerDictionary.TryGetValue(key, out var cacheItem))
            {
                item = cacheItem;
                return true;
            }
        }
        finally
        {
            _rwLock.ExitReadLock();
        }

        item = default;
        return false;
    }

    /// <summary>
    /// Retrieves an array of items from the inner dictionary.
    /// </summary>
    /// <typeparam name="TItem">The type of the items in the dictionary.</typeparam>
    /// <returns>An array of the items in the dictionary.</returns>
    public TItem[] GetItems()
    {
        _rwLock.EnterReadLock();
        try
        {
            return _innerDictionary.Values.ToArray();
        }
        finally
        {
            _rwLock.ExitReadLock();
        }
    }

    /// <summary>
    /// Clears all the items from the inner dictionary.
    /// </summary>
    public void Clear()
    {
        _rwLock.EnterWriteLock();
        try
        {
            foreach (var (key, _) in _innerDictionary) Remove(key);
        }
        finally
        {
            _rwLock.ExitWriteLock();
        }
    }

    /// <summary>
    /// Determines whether the dictionary contains the specified key.
    /// </summary>
    /// <param name="key">The key to locate in the dictionary.</param>
    /// <returns>
    /// <c>true</c> if the dictionary contains an element with the specified key; otherwise, <c>false</c>.
    /// </returns>
    public bool Contains(byte[] key)
    {
        _rwLock.EnterReadLock();
        try
        {
            return _innerDictionary.TryGetValue(key, out _);
        }
        finally
        {
            _rwLock.ExitReadLock();
        }
    }

    /// <summary>
    /// Filters the entries in the collection asynchronously based on a specified condition.
    /// </summary>
    /// <param name="expression">The async predicate function to test each entry.</param>
    /// <returns>A task that represents the asynchronous operation. The task result contains an array of key-value pairs that satisfy the specified condition.</returns>
    public ValueTask<KeyValuePair<byte[], TItem>[]> WhereAsync(
        Func<KeyValuePair<byte[], TItem>, ValueTask<bool>> expression)
    {
        Guard.Argument(expression, nameof(expression)).NotNull();
        _rwLock.EnterReadLock();
        try
        {
            var entries = IterateAsync().WhereAwait(expression).ToArrayAsync();
            return entries;
        }
        finally
        {
            _rwLock.ExitReadLock();
        }
    }

    /// <summary>
    /// Filters the elements of the collection based on a specified condition.
    /// </summary>
    /// <param name="expression">The function used to filter the collection.</param>
    /// <returns>
    /// An <see cref="IEnumerable{T}"/> containing the key-value pairs from the collection that satisfy the condition
    /// specified by <paramref name="expression"/>.
    /// </returns>
    public IEnumerable<KeyValuePair<byte[], TItem>> Where(Func<KeyValuePair<byte[], TItem>, bool> expression)
    {
        Guard.Argument(expression, nameof(expression)).NotNull();

        _rwLock.EnterReadLock();
        try
        {
            var entries = IterateAsync().Where(expression).ToEnumerable();
            return entries;
        }
        finally
        {
            _rwLock.ExitReadLock();
        }
    }

    /// <summary>
    /// Retrieves an asynchronous enumerator that iterates through the elements of the dictionary.
    /// </summary>
    /// <returns>
    /// An asynchronous enumerable collection of key-value pairs representing the elements of the dictionary.
    /// </returns>
    private IAsyncEnumerable<KeyValuePair<byte[], TItem>> IterateAsync()
    {
        _rwLock.EnterReadLock();
        try
        {
            return _innerDictionary.ToAsyncEnumerable();
        }
        finally
        {
            _rwLock.ExitReadLock();
        }
    }
}