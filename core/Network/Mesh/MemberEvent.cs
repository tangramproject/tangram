using System.Linq;

namespace TangramXtgm.Network.Mesh;

using System;
using System.IO;
using System.Net;

public class MemberEvent
{
    public IPEndPoint SenderGossipEndPoint;
    public DateTime ReceivedDateTime;

    public MemberState State { get; private set; }
    public IPAddress IP { get; private set; }
    public ushort GossipPort { get; private set; }
    public byte Generation { get; private set; }
    public uint Service { get; private set; }
    public byte[] ServiceName { get; private set; }
    public byte[] ServiceVersion { get; private set; }
    public byte[] PublicKey { get; private set; }
    public ushort ServicePort { get; private set; }

    public IPEndPoint GossipEndPoint => new(IP, GossipPort);

    private MemberEvent()
    {
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="senderGossipEndPoint"></param>
    /// <param name="receivedDateTime"></param>
    /// <param name="ip"></param>
    /// <param name="gossipPort"></param>
    /// <param name="state"></param>
    /// <param name="generation"></param>
    internal MemberEvent(IPEndPoint senderGossipEndPoint, DateTime receivedDateTime, IPAddress ip, ushort gossipPort, MemberState state, byte generation)
    {
        SenderGossipEndPoint = senderGossipEndPoint;
        ReceivedDateTime = receivedDateTime;

        IP = ip;
        GossipPort = gossipPort;
        State = state;
        Generation = generation;
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="senderGossipEndPoint"></param>
    /// <param name="receivedDateTime"></param>
    /// <param name="member"></param>
    internal MemberEvent(IPEndPoint senderGossipEndPoint, DateTime receivedDateTime, Member member)
    {
        SenderGossipEndPoint = senderGossipEndPoint;
        ReceivedDateTime = receivedDateTime;

        IP = member.IP;
        GossipPort = member.GossipPort;
        State = member.State;
        Generation = member.Generation;
        Service = member.Service;
        ServicePort = member.ServicePort;
        PublicKey = member.PublicKey;
        ServiceName = member.ServiceName;
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="senderGossipEndPoint"></param>
    /// <param name="receivedDateTime"></param>
    /// <param name="stream"></param>
    /// <param name="isSender"></param>
    /// <returns></returns>
    internal static MemberEvent ReadFrom(IPEndPoint senderGossipEndPoint, DateTime receivedDateTime, Stream stream, bool isSender = false)
    {
        if (stream.Position >= stream.Length)
        {
            return null;
        }

        var memberEvent = new MemberEvent
        {
            SenderGossipEndPoint = senderGossipEndPoint,
            ReceivedDateTime = receivedDateTime,

            IP = isSender ? senderGossipEndPoint.Address : stream.ReadIPAddress(),
            GossipPort = isSender ? (ushort)senderGossipEndPoint.Port : stream.ReadPort(),
            State = isSender ? MemberState.Alive : stream.ReadMemberState(),
            Generation = (byte)stream.ReadByte(),
        };

        if (memberEvent.State != MemberState.Alive) return memberEvent;
        memberEvent.Service = stream.ReadService();
        memberEvent.ServicePort = stream.ReadPort();
        memberEvent.PublicKey = stream.ReadPublicKey()[..33];
        memberEvent.ServiceName = stream.ReadServiceName();

        return memberEvent;
    }

    /// <summary>
    /// 
    /// </summary>
    /// <returns></returns>
    public override string ToString()
    {
        return
            $"Sender:{SenderGossipEndPoint} Received:{ReceivedDateTime} IP:{IP} GossipPort:{GossipPort} State:{State} Generation:{Generation} Service:{Service} ServicePort:{ServicePort}";
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="memberEvent"></param>
    /// <returns></returns>
    public bool Equal(MemberEvent memberEvent)
    {
        return memberEvent != null &&
                IP.Equals(memberEvent.IP) &&
                GossipPort == memberEvent.GossipPort &&
                State == memberEvent.State &&
                Generation == memberEvent.Generation &&
                Service == memberEvent.Service &&
                PublicKey.SequenceEqual(memberEvent.PublicKey) &&
                ServicePort == memberEvent.ServicePort &&
                ServiceName.SequenceEqual(memberEvent.ServiceName) &&
                ServiceVersion == memberEvent.ServiceVersion;
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="memberEvent"></param>
    /// <returns></returns>
    public bool NotEqual(MemberEvent memberEvent)
    {
        return !Equal(memberEvent);
    }
}