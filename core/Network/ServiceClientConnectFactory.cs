
using nng;
using nng.Native;
using TangramXtgm.Helper;

namespace TangramXtgm.Network;

using System.Net;

/// <summary>
/// Represents a service client.
/// </summary>
public interface IServiceClient
{
    IPEndPoint ServiceEndPoint { get; set; }
}

/// <summary>
/// Represents a factory for creating service client instances.
/// </summary>
public interface IServiceClientFactory
{
    IServiceClient CreateServiceClient(IPEndPoint serviceEndPoint);
}

/// <summary>
/// Represents a client for accessing a service.
/// </summary>
public class ServiceClient : IServiceClient
{
    public IPEndPoint ServiceEndPoint { get; set; }
    public IReqSocket Socket { get; set; }
}

/// <summary>
/// Represents a factory for creating service client instances.
/// </summary>
public class ServiceClientConnectFactory : IServiceClientFactory
{
    /// <summary>
    /// Creates a service client with the specified service endpoint.
    /// </summary>
    /// <param name="serviceEndPoint">The service endpoint to connect to.</param>
    /// <returns>A new instance of <see cref="IServiceClient"/> configured with the provided service endpoint.</returns>
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