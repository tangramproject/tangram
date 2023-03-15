using System.Threading.Tasks;

namespace TangramXtgm.Network.Mesh;

public interface IMemberListener
{
    Task MemberUpdatedCallback(MemberEvent memberEvent);
}