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
using TangramXtgm.Helper;
using TangramXtgm.Models;
using TangramXtgm.Models.Messages;
using TangramXtgm.Network;
using Block = TangramXtgm.Models.Block;

namespace TangramXtgm.Ledger;

/// <summary>
/// </summary>
public interface ISync
{
    bool Running { get; }
}

/// <summary>
/// </summary>
public class Sync : ISync, IDisposable
{
    private const int RetryCount = 6;
    private readonly ISystemCore _systemCore;
    private readonly ILogger _logger;
    private IDisposable _disposableInit;

    private bool _disposed;
    private int _running;

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

    public bool Running => _running != 0;

    /// <summary>
    /// </summary>
    private void Init()
    {
        _disposableInit = Observable
            .Timer(TimeSpan.Zero, TimeSpan.FromMinutes(_systemCore.Node.Network.AutoSyncEveryMinutes))
            .SubscribeOn(Scheduler.Default).Subscribe(o =>
            {
                if (_systemCore.ApplicationLifetime.ApplicationStopping.IsCancellationRequested) return;
                try
                {
                    if (Running) return;
                    AsyncHelper.RunSync(async () =>
                    {
                        var currentRetry = 0;

                        await AnsiConsole.Progress().AutoClear(false).Columns(new TaskDescriptionColumn(), new ProgressBarColumn(),
                            new PercentageColumn(), new SpinnerColumn()).StartAsync(async ctx =>
                        {
                            var warpTask = ctx.AddTask($"[bold green]WAITING FOR PEERS[/]", false).IsIndeterminate();
                            warpTask.MaxValue(63);
                            warpTask.StartTask();
                            warpTask.IsIndeterminate(false);
                            while (!ctx.IsFinished)
                            {
                                if (_systemCore.ApplicationLifetime.ApplicationStopping.IsCancellationRequested)
                                    return;

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

                                warpTask.Description = $"[bold blue]WAITING FOR PEERS[/]... [bold yellow]RETRYING in {retryDelay.Seconds}s[/]";
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

                    });
                    Interlocked.Exchange(ref _running, 1);
                    Synchronize();
                }
                catch (TaskCanceledException)
                {
                    // Ignore
                }
            });
    }

    /// <summary>
    /// </summary>
    /// <returns></returns>
    private void Synchronize()
    {
        _logger.Information("Begin... [SYNCHRONIZATION]");
        try
        {
            var blockCount = _systemCore.UnitOfWork().HashChainRepository.Count;
            _logger.Information("OPENING block height [{@Height}]", blockCount - 1);
            var peers = _systemCore.PeerDiscovery().GetGossipMemberStore();
            if (peers.Any() != true) return;
            var maxBlockCount = AsyncHelper.RunSync(async () => await _systemCore.PeerDiscovery().NetworkBlockCountAsync());
            var chunk = maxBlockCount / (ulong)peers.Length;
            _logger.Information("Peer count [{@PeerCount}]", peers.Length);
            _logger.Information("Network block height [{@MaxBlockHeight}]", maxBlockCount - 1);
            foreach (var peer in peers)
            {
                var skip = blockCount <= 6 ? blockCount : blockCount - 6; // +- Depth of blocks to compare.
                var take = (int)blockCount + (int)chunk;
                if (take > (int)maxBlockCount)
                {
                    take = (int)(maxBlockCount - blockCount) + (int)blockCount;
                }
                AsyncHelper.RunSync(async () => await SynchronizeAsync(peer, skip, take));
                blockCount = _systemCore.UnitOfWork().HashChainRepository.Count;
                if (blockCount == maxBlockCount) break;
            }
        }
        catch (Exception ex)
        {
            _logger.Here().Error(ex, "Error while checking");
        }
        finally
        {
            Interlocked.Exchange(ref _running, 0);
            var blockCount = _systemCore.UnitOfWork().HashChainRepository.Count;
            _logger.Information("LOCAL NODE block height: [{@LocalHeight}]", blockCount - 1);
            _logger.Information("End... [SYNCHRONIZATION]");
            _logger.Information("Next...[SYNCHRONIZATION] in {@Message} minute(s)",
                _systemCore.Node.Network.AutoSyncEveryMinutes);
        }
    }

    /// <summary>
    /// </summary>
    /// <param name="peer"></param>
    /// <param name="skip"></param>
    /// <param name="take"></param>
    /// <returns></returns>
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
                        var n = blocks.Count - (int)x;
                        _logger.Information("TAKING LONGEST CHAIN");
                        blocks = blocks.Skip(n).ToList();
                    }
                }
                else
                {
                    _logger.Information("CHECKING [FORK RULE]");
                    var forkRuleBlocks = await validator.ForkRuleAsync(blocks.OrderBy(x => x.Height).ToArray());
                    if (forkRuleBlocks.Length == 0)
                    {
                        _logger.Fatal("FORK RULE [UNABLE TO VERIFY]");
                        return;
                    }

                    blocks = forkRuleBlocks.ToList();
                    _logger.Information("FORK RULE CHECK [OK]");
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
                                warpTask.Description = $"[bold green]SYNCHRONIZED BLOCK HEIGHT[/] [bold yellow]{block.Height}[/]";
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
    /// </summary>
    /// <param name="peer"></param>
    /// <param name="skip"></param>
    /// <param name="take"></param>
    /// <returns></returns>
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
    /// 
    /// </summary>
    /// <param name="disposing"></param>
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
    /// 
    /// </summary>
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }
}