using System;
using System.Threading.Tasks;
using Dawn;
using Serilog;
using TangramXtgm.Extensions;
using TangramXtgm.Network.Mesh;

namespace TangramXtgm.Network;

/// <summary>
/// 
/// </summary>
public class MemberListener: IMemberListener
{
    private readonly IGossipMemberStore _gossipMemberStore;
    private readonly IGossipMemberEventsStore _gossipMemberEvents;
    private readonly ILogger _logger;

    /// <summary>
    /// 
    /// </summary>
    /// <param name="gossipMemberStore"></param>
    /// <param name="gossipMemberEvents"></param>
    /// <param name="logger"></param>
    public MemberListener(IGossipMemberStore gossipMemberStore, IGossipMemberEventsStore gossipMemberEvents, ILogger logger)
    {
        _gossipMemberStore = gossipMemberStore;
        _gossipMemberEvents = gossipMemberEvents;
        _logger = logger;
    }
        
    /// <summary>
    /// 
    /// </summary>
    /// <param name="memberEvent"></param>
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