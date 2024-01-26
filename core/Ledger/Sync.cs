// Tangram by Matthew Hellyer is licensed under CC BY-NC-ND 4.0.
// To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Reactive.Concurrency;
using System.Reactive.Linq;
using System.Threading;
using System.Threading.Tasks;
using TangramXtgm.Extensions;
using Dawn;
using MessagePack;
using Serilog;
using Spectre.Console;
using TangramXtgm.Models;
using TangramXtgm.Models.Messages;
using TangramXtgm.Network;
using Block = TangramXtgm.Models.Block;

namespace TangramXtgm.Ledger;

/// <summary>
/// Represents an interface for syncing operations.
/// </summary>
public interface ISync
{
    bool SyncRunning { get; }
    Task SetSyncRunningAsync(bool isRunning);
    Task SynchronizeAsync();
}

/// <summary>
/// Represents a class for synchronizing the system with other peers.
/// </summary>
public class Sync : ISync, IDisposable
{
    private const int RetryCount = 6;
    private readonly ISystemCore _systemCore;
    private readonly ILogger _logger;
    private IDisposable _disposableInit;

    private bool _disposed;
    private int _syncRunning;

    /// <summary>
    /// </summary>
    /// <param name="systemCore"></param>
    /// <param name="logger"></param>
    public Sync(ISystemCore systemCore, ILogger logger)
    {
        _systemCore = systemCore;
        _logger = logger.ForContext("SourceContext", nameof(Sync));
        Init();
    }

    /// <summary>
    /// Gets a value indicating whether the object is currently running.
    /// </summary>
    /// <value>
    /// <c>true</c> if the object is running; otherwise, <c>false</c>.
    /// </value>
    public bool SyncRunning => _syncRunning != 0;

    /// <summary>
    /// Initializes the object.
    /// </summary>
    private void Init()
    {
        _disposableInit = Observable
            .Timer(TimeSpan.Zero)
            .SubscribeOn(Scheduler.Default).Subscribe(OnNext);
    }

    /// <summary>
    /// Sets the sync running state asynchronously.
    /// </summary>
    /// <param name="isRunning">The boolean value indicating whether the sync is running or not.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    public async Task SetSyncRunningAsync(bool isRunning)
    {
        // If trying to set SyncRunning to 'true' and it's already 'true'
        if (isRunning && SyncRunning)
        {
            while (SyncRunning)
            {
                await Task.Delay(500);
            }
        }
        // Thread-safe way to set _syncRunning.
        Interlocked.Exchange(ref _syncRunning, isRunning ? 1 : 0);
    }

    /// <summary>
    /// This method is called when a new value is received.
    /// </summary>
    /// <param name="o">The value received.</param>
    private async void OnNext(long o)
    {
        if (_systemCore.ApplicationLifetime.ApplicationStopping.IsCancellationRequested) return;
        try
        {
            if (SyncRunning) return;
            var currentRetry = 0;

            await AnsiConsole.Progress()
                .AutoClear(false)
                .Columns(new TaskDescriptionColumn(), new ProgressBarColumn(), new PercentageColumn(),
                    new SpinnerColumn())
                .StartAsync(async ctx =>
                {
                    var warpTask = ctx.AddTask($"[bold green]WAITING FOR PEERS[/]", false).IsIndeterminate();
                    warpTask.MaxValue(63);
                    warpTask.StartTask();
                    warpTask.IsIndeterminate(false);
                    while (!ctx.IsFinished)
                    {
                        if (_systemCore.ApplicationLifetime.ApplicationStopping.IsCancellationRequested) return;

                        var jitter = new Random();
                        var discovery = _systemCore.PeerDiscovery();
                        if (currentRetry >= RetryCount || discovery.Count() != 0)
                        {
                            warpTask.Description = "[bold green]PEERS FOUND[/]...";
                            await Task.Delay(1);
                            warpTask.Increment(63);
                            warpTask.StopTask();
                            return;
                        }

                        var retryDelay = TimeSpan.FromSeconds(Math.Pow(2, currentRetry)) +
                                         TimeSpan.FromMilliseconds(jitter.Next(0, 1000));
                        warpTask.Description =
                            $"[bold blue]WAITING FOR PEERS[/]... [bold yellow]RETRYING in {retryDelay.Seconds}s[/]";
                        await Task.Delay(retryDelay);
                        await Task.Delay(1);
                        warpTask.Increment(retryDelay.Seconds);
                        if (retryDelay.Seconds == 32)
                        {
                            warpTask.Description = "[bold red]NO PEERS FOUND[/]...";
                            await Task.Delay(1);
                            warpTask.StopTask();
                            return;
                        }

                        currentRetry++;
                    }
                });
            await SynchronizeAsync();
        }
        catch (TaskCanceledException)
        {
            // Ignore
        }
    }

    /// <summary>
    /// Asynchronously synchronizes the system with other peers in the network.
    /// </summary>
    /// <returns>A task representing the asynchronous operation.</returns>
    public async Task SynchronizeAsync()
    {
        _logger.Information("Begin... [SYNCHRONIZATION]");
        await SetSyncRunningAsync(true);

        try
        {
            var blockCount = _systemCore.UnitOfWork().HashChainRepository.Count;
            _logger.Information("OPENING block height [{@Height}]",
                _systemCore.UnitOfWork().HashChainRepository.Height);
            var peers = _systemCore.PeerDiscovery().GetGossipMemberStore();
            _logger.Information("Peer count [{@PeerCount}]", peers.Length);

            if (peers.Any())
            {
                var maxBlockCount = await _systemCore.PeerDiscovery().NetworkBlockCountAsync();
                _logger.Information("Network block height [{@MaxBlockHeight}]",
                    maxBlockCount = maxBlockCount == 0 ? 0 : maxBlockCount - 1);

                // number of total chunks
                var chunk = (maxBlockCount - blockCount) / (ulong)peers.Length;
                var remainder = (maxBlockCount - blockCount) % (ulong)peers.Length; // calculate the remainder 

                var tasks = new List<Task>();
                var throttle = new SemaphoreSlim(Environment.ProcessorCount); // Restrict to max number of processors.

                var startBlockHeight = blockCount;

                foreach (var peer in peers)
                {
                    await throttle.WaitAsync(); // blocks if count >= maximum concurrent tasks.
                    tasks.Add(Task.Run(async () =>
                    {
                        try
                        {
                            var chunkSize = chunk;
                            // distribute remainder chunks across peers
                            if (remainder > 0)
                            {
                                chunkSize++;
                                remainder--;
                            }

                            var endBlockHeight = startBlockHeight + chunkSize;
                            if (endBlockHeight > maxBlockCount)
                            {
                                endBlockHeight = maxBlockCount;
                            }

                            var peerBlockCount = await _systemCore.PeerDiscovery().PeerBlockCountAsync(peer);
                            if (blockCount >= peerBlockCount) return;
                            await SynchronizeAsync(peer, startBlockHeight, (int)endBlockHeight + 1);
                            startBlockHeight += chunkSize; // incrementing start block height for the next peer
                        }
                        finally
                        {
                            throttle.Release();
                        }
                    }));
                }

                await Task.WhenAll(tasks);
            }
        }
        catch (Exception ex)
        {
            _logger.Here().Error(ex, "Error while checking");
        }
        finally
        {
            await SetSyncRunningAsync(false);
            var blockCount = _systemCore.UnitOfWork().HashChainRepository.Count;
            _logger.Information("End... [SYNCHRONIZATION]");
        }
    }

    /// <summary>
    /// Synchronizes the blockchain with a peer asynchronously.
    /// </summary>
    /// <param name="peer">The peer to synchronize with.</param>
    /// <param name="skip">The number of blocks to skip before synchronizing.</param>
    /// <param name="take">The maximum number of blocks to synchronize.</param>
    /// <returns>A task representing the asynchronous synchronization process.</returns>
    private async Task SynchronizeAsync(Peer peer, ulong skip, int take)
    {
        Guard.Argument(peer, nameof(peer)).HasValue();
        Guard.Argument(take, nameof(take)).NotNegative();
        try
        {
            var validator = _systemCore.Validator();
            var blocks = await FetchBlocksAsync(peer, skip, take);
            if (blocks?.Any() != true) return;
            if (skip != 0)
            {
                _logger.Information("CONTINUE BOOTSTRAPPING");
                _logger.Information("CHECKING [BLOCK DUPLICATES]");
                var verifyNoDuplicateBlockHeights = validator.VerifyBlocksWithNoDuplicateHeights(blocks);
                if (verifyNoDuplicateBlockHeights == VerifyResult.AlreadyExists)
                {
                    _systemCore.PeerDiscovery().SetPeerCooldown(new PeerCooldown
                    {
                        IpAddress = peer.IpAddress,
                        PublicKey = peer.PublicKey,
                        NodeId = peer.NodeId,
                        PeerState = PeerState.DupBlocks
                    });
                    _logger.Warning("DUPLICATE block height [UNABLE TO VERIFY]");
                    return;
                }

                var blockCount = _systemCore.UnitOfWork().HashChainRepository.Count;
                var peerBlockCount = await _systemCore.PeerDiscovery().PeerBlockCountAsync(peer);
                if (blockCount != peerBlockCount)
                {
                    if (blockCount < peerBlockCount)
                    {
                        var x = peerBlockCount - (blockCount + 1);
                        var n = blocks.Count - (int)x - 1;
                        _logger.Information("TAKING LONGEST CHAIN");
                        blocks = blocks.Skip(n).ToList();
                    }
                }
                else
                {
                    _logger.Information("BLOCK HEIGHTS MATCH");
                }
            }
            else
            {
                _logger.Warning("FIRST TIME BOOTSTRAPPING");
            }

            await AnsiConsole.Progress().AutoClear(false).Columns(new TaskDescriptionColumn(), new ProgressBarColumn(),
                new PercentageColumn(), new SpinnerColumn()).StartAsync(async ctx =>
            {
                var warpTask = ctx.AddTask($"[bold green]SYNCHRONIZING[/] [bold yellow]{blocks.Count}[/] Block(s)", false).IsIndeterminate();
                warpTask.MaxValue(blocks.Count);
                warpTask.StartTask();
                warpTask.IsIndeterminate(false);
                while (!ctx.IsFinished)
                    foreach (var block in blocks.OrderBy(x => x.Height))
                        try
                        {
                            var saveBlockResponse =
                                await _systemCore.Graph().SaveBlockAsync(new SaveBlockRequest(block));
                            if (saveBlockResponse.Ok)
                            {
                                await Task.Delay(1);
                                warpTask.Increment(1);
                                continue;
                            }

                            warpTask.StopTask();
                            return;
                        }
                        catch (Exception ex)
                        {
                            warpTask.StopTask();
                            _logger.Here().Error(ex, "Unable to save block: {@Hash}", block.Hash.ByteToHex());
                            return;
                        }
            });
        }
        catch (Exception ex)
        {
            _logger.Here().Error(ex, "SYNCHRONIZATION [FAILED]");
        }
    }

    /// <summary>
    /// Fetches blocks asynchronously from a peer.
    /// </summary>
    /// <param name="peer">The peer from which to fetch the blocks.</param>
    /// <param name="skip">The number of blocks to skip.</param>
    /// <param name="take">The number of blocks to fetch.</param>
    /// <returns>A task representing the asynchronous operation. The task result contains the fetched blocks as a read-only list.</returns>
    private async Task<IReadOnlyList<Block>> FetchBlocksAsync(Peer peer, ulong skip, int take)
    {
        Guard.Argument(peer, nameof(peer)).HasValue();
        Guard.Argument(take, nameof(take)).NotNegative();
        var iSkip = skip;
        try
        {
            const int maxBlocks = 10;
            var iTake = take - (int)skip;
            var chunks = Enumerable.Repeat(maxBlocks, iTake / maxBlocks).ToList();
            if (iTake % maxBlocks != 0) chunks.Add(iTake % maxBlocks);

            // Show progress
            var blocks = await AnsiConsole.Progress().AutoClear(false).Columns(new TaskDescriptionColumn(),
                    new ProgressBarColumn(), new PercentageColumn(), new SpinnerColumn())
                .StartAsync(async ctx =>
                {
                    var blocks = new List<Block>();
                    var warpTask = ctx
                        .AddTask(
                            $"[bold green]DOWNLOADING[/] [bold yellow]{Math.Abs(take - (int)skip)}[/] block(s) from [bold yellow]{peer.Name.FromBytes()}[/]",
                            false).IsIndeterminate();
                    warpTask.MaxValue(take - (int)skip);
                    warpTask.StartTask();
                    warpTask.IsIndeterminate(false);
                    while (!ctx.IsFinished)
                        foreach (var chunk in chunks)
                        {
                            var blocksResponse = await _systemCore.GossipMemberStore().SendAsync<BlocksResponse>(
                                new IPEndPoint(IPAddress.Parse(peer.IpAddress.FromBytes()), peer.TcpPort.ToInt32()),
                                peer.PublicKey,
                                MessagePackSerializer.Serialize(new Parameter[]
                                {
                                    new() { Value = iSkip.ToBytes(), ProtocolCommand = ProtocolCommand.GetBlocks },
                                    new() { Value = chunk.ToBytes(), ProtocolCommand = ProtocolCommand.GetBlocks }
                                }));
                            if (blocksResponse?.Blocks is null)
                            {
                                warpTask.StopTask();
                                break;
                            }
                            blocks.AddRange(blocksResponse.Blocks);
                            iSkip += (ulong)chunk;
                            await Task.Delay(100);
                            warpTask.Increment(chunk);
                        }
                    return blocks;
                });
            return blocks;
        }
        catch (Exception ex)
        {
            _logger.Here().Error("{@Message}", ex.Message);
        }

        return null;
    }

    /// <summary>
    /// Performs application-defined tasks associated with freeing, releasing, or resetting
    /// unmanaged resources and optionally releases managed resources.
    /// </summary>
    /// <param name="disposing">True to release both managed and unmanaged resources;
    /// false to release only unmanaged resources.</param>
    private void Dispose(bool disposing)
    {
        if (_disposed)
        {
            return;
        }

        if (disposing)
        {
            _disposableInit?.Dispose();
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