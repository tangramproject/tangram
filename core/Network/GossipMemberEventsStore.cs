using System.Collections.Generic;
using Dawn;
using TangramXtgm.Network.Mesh;

namespace TangramXtgm.Network;

/// <summary>
/// Represents a store for gossip member events.
/// </summary>
public interface IGossipMemberEventsStore
{
    void Add(MemberEvent memberEvent);
    MemberEvent[] GetAll();
}

/// <summary>
/// Represents a store for storing and retrieving member events in a gossip-based system.
/// </summary>
public class GossipMemberEventsStore : IGossipMemberEventsStore
{
    private readonly object _memberEventsLocker = new();
    private readonly List<MemberEvent> _memberEvents = new();

    /// <summary>
    /// Adds a MemberEvent to the collection.
    /// </summary>
    /// <param name="memberEvent">The MemberEvent to add.</param>
    public void Add(MemberEvent memberEvent)
    {
        Guard.Argument(memberEvent, nameof(memberEvent)).NotNull();
        lock (_memberEventsLocker)
        {
            _memberEvents.Add(memberEvent);
        }
    }

    /// <summary>
    /// Retrieves all MemberEvent objects.
    /// </summary>
    /// <returns>An array of MemberEvent objects.</returns>
    public MemberEvent[] GetAll()
    {
        lock (_memberEventsLocker)
        {
            return _memberEvents.ToArray();
        }
    }
}