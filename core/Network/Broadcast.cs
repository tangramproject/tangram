// Tangram by Matthew Hellyer is licensed under CC BY-NC-ND 4.0.
// To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0

using System;
using System.Linq;
using System.Threading.Tasks;
using System.Threading.Tasks.Dataflow;
using TangramXtgm.Extensions;
using MessagePack;
using Serilog;
using TangramXtgm.Helper;
using TangramXtgm.Models;
using TangramXtgm.Models.Messages;

namespace TangramXtgm.Network;

/// <summary>
/// 
/// </summary>
public interface IBroadcast
{
    /// <summary>
    /// </summary>
    /// <param name="value"></param>
    Task PostAsync((TopicType, byte[]) value);
}

/// <summary>
/// </summary>
public class Broadcast : ReceivedActor<(TopicType, byte[])>, IBroadcast
{
    private readonly ISystemCore _systemCore;
    private readonly ILogger _logger;

    /// <summary>
    /// </summary>
    /// <param name="systemCore"></param>
    /// <param name="logger"></param>
    public Broadcast(ISystemCore systemCore, ILogger logger) : base(
        new ExecutionDataflowBlockOptions { BoundedCapacity = 100, MaxDegreeOfParallelism = 2, EnsureOrdered = true })
    {
        _systemCore = systemCore;
        _logger = logger.ForContext("SourceContext", nameof(Broadcast));
    }

    /// <summary>
    /// </summary>
    /// <param name="values"></param>
    public new async Task PostAsync((TopicType, byte[]) values)
    {
        await base.PostAsync(values);
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="message"></param>
    protected override async Task OnReceiveAsync((TopicType, byte[]) message)
    {
        try
        {
            var (topicType, data) = message;
            var peers = await _systemCore.PeerDiscovery().GetDiscoveryAsync();
            if (peers.Any())
            {
                var command = topicType switch
                {
                    TopicType.AddTransaction => ProtocolCommand.Transaction,
                    _ => ProtocolCommand.BlockGraph
                };
                var msg = MessagePackSerializer.Serialize(new Parameter[]
                {
                    new() { ProtocolCommand = command, Value = data }
                });
                await Parallel.ForEachAsync(peers, (knownPeer, cancellationToken) =>
                {
                    try
                    {
                        if (cancellationToken.IsCancellationRequested) return ValueTask.CompletedTask;
                        var _ = _systemCore.P2PDeviceReq().SendAsync<EmptyMessage>(knownPeer.IpAddress,
                            knownPeer.TcpPort,
                            knownPeer.PublicKey, msg, 250).SafeForgetAsync(_logger).ConfigureAwait(false);
                    }
                    catch (Exception)
                    {
                        // Ignore
                    }

                    return ValueTask.CompletedTask;
                });
            }
            else
            {
                _logger.Warning("Broadcast no peers");
            }
        }
        catch (Exception ex)
        {
            _logger.Here().Error("{@Message}", ex.Message);
        }
    }
}