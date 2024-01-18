using System;
using System.Threading.Tasks;
using Dawn;
using Serilog;
using TangramXtgm.Extensions;
using TangramXtgm.Network.Mesh;

namespace TangramXtgm.Network;

/// <summary>
/// A class that implements the IMemberListener interface.
/// </summary>
public class MemberListener : IMemberListener
{
    private readonly IGossipMemberStore _gossipMemberStore;
    private readonly IGossipMemberEventsStore _gossipMemberEvents;
    private readonly ILogger _logger;

    /// <summary>
    /// Represents a listener for gossip members.
    /// </summary>
    /// <param name="gossipMemberStore">The gossip member store implementation.</param>
    /// <param name="gossipMemberEvents">The gossip member events store implementation.</param>
    /// <param name="logger">The logger implementation for logging events.</param>
    public MemberListener(IGossipMemberStore gossipMemberStore, IGossipMemberEventsStore gossipMemberEvents,
        ILogger logger)
    {
        _gossipMemberStore = gossipMemberStore;
        _gossipMemberEvents = gossipMemberEvents;
        _logger = logger;
    }

    /// <summary>
    /// Callback method that gets invoked when a member is updated.
    /// </summary>
    /// <param name="memberEvent">The MemberEvent containing information about the updated member.</param>
    /// <returns>A Task representing the asynchronous operation.</returns>
    public Task MemberUpdatedCallback(MemberEvent memberEvent)
    {
        Guard.Argument(memberEvent, nameof(memberEvent)).NotNull();
        try
        {
            _gossipMemberEvents.Add(memberEvent);
            _gossipMemberStore.AddOrUpdateNode(memberEvent);
        }
        catch (Exception ex)
        {
            _logger.Here().Error("{Message}", ex.Message);
        }

        return Task.CompletedTask;
    }
}