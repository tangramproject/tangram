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
/// Represents a broadcast service for sending messages using topics.
/// </summary>
public interface IBroadcast
{
    /// <summary>
    /// </summary>
    /// <param name="value"></param>
    Task PostAsync((TopicType, byte[]) value);
}

/// <summary>
/// Represents a class that broadcasts messages to all members of a system.
/// </summary>
public class Broadcast : ReceivedActor<(TopicType, byte[])>, IBroadcast
{
    private readonly ISystemCore _systemCore;
    private readonly ILogger _logger;

    /// <summary>
    /// Represents a broadcast block that sends messages to multiple targets.
    /// </summary>
    /// <param name="systemCore">The system core instance.</param>
    /// <param name="logger">The logger instance.</param>
    public Broadcast(ISystemCore systemCore, ILogger logger) : base(
        new ExecutionDataflowBlockOptions { BoundedCapacity = 100, MaxDegreeOfParallelism = 2, EnsureOrdered = true })
    {
        _systemCore = systemCore;
        _logger = logger.ForContext("SourceContext", nameof(Broadcast));
    }

    /// <summary>
    /// Makes a POST request to the specified endpoint.
    /// </summary>
    /// <param name="values">The tuple consisting of the topic type and byte array values to be sent in the body of the request.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    public new async Task PostAsync((TopicType, byte[]) values)
    {
        await base.PostAsync(values);
    }

    /// <summary>
    /// Method for processing received messages asynchronously.
    /// </summary>
    /// <param name="message">The received message, which is a tuple containing the topic type and the message data.</param>
    /// <returns>A Task representing the asynchronous operation.</returns>
    protected override async Task OnReceiveAsync((TopicType, byte[]) message)
    {
        try
        {
            var (topicType, data) = message;
            var command = topicType switch
            {
                TopicType.AddTransaction => ProtocolCommand.Transaction,
                TopicType.OnNewBlock => ProtocolCommand.OnNewBlock,
                _ => ProtocolCommand.BlockGraph
            };
            await _systemCore.GossipMemberStore().SendAllAsync(MessagePackSerializer.Serialize(new Parameter[]
            {
                new() { ProtocolCommand = command, Value = data }
            }));
        }
        catch (Exception ex)
        {
            _logger.Here().Error("{@Message}", ex.Message);
        }
    }
}