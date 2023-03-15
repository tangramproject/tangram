
using nng;
using nng.Native;
using TangramXtgm.Helper;

namespace TangramXtgm.Network;

using System.Net;

/// <summary>
/// 
/// </summary>
public interface IServiceClient
{
    IPEndPoint ServiceEndPoint { get; set; }
}

/// <summary>
/// 
/// </summary>
public interface IServiceClientFactory
{
    IServiceClient CreateServiceClient(IPEndPoint serviceEndPoint);
}

/// <summary>
/// 
/// </summary>
public class ServiceClient : IServiceClient
{
    public IPEndPoint ServiceEndPoint { get; set; }
    public IReqSocket Socket { get; set; }
}

/// <summary>
/// 
/// </summary>
public class ServiceClientConnectFactory: IServiceClientFactory
{
    /// <summary>
    /// 
    /// </summary>
    /// <param name="serviceEndPoint"></param>
    /// <returns></returns>
    public IServiceClient CreateServiceClient(IPEndPoint serviceEndPoint)
    {
        var socket = NngFactorySingleton.Instance.Factory.RequesterOpen()
            .ThenDial($"tcp://{serviceEndPoint}", Defines.NngFlag.NNG_FLAG_NONBLOCK).Unwrap();
        return new ServiceClient
        {
            Socket = socket,
            ServiceEndPoint = serviceEndPoint
        };
    }
}