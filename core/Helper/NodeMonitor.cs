using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using TangramXtgm.Extensions;
using Serilog;
using TangramXtgm.Models;

namespace TangramXtgm.Helper;

public interface INodeMonitor
{
    public bool Start();
    public void Stop();
    public Task<bool> ConnectAsync(CancellationToken cancellationToken);
}

public class NodeMonitor : INodeMonitor
{
    private readonly Socket _client;
    private readonly NodeMonitorConfigurationOptions _configuration;

    private readonly IPEndPoint _endPoint;
    private readonly ILogger _logger;

    public NodeMonitor(NodeMonitorConfigurationOptions configuration, ILogger logger)
    {
        _logger = logger.ForContext("SourceContext", nameof(NodeMonitor));
        _configuration = configuration;

        if (_configuration.Enabled)
            try
            {
                var ipAddress = IPAddress.Parse(_configuration.Tester.Listening);
                _endPoint = new IPEndPoint(ipAddress, _configuration.Tester.Port);
                _client = new Socket(ipAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            }
            catch (Exception ex)
            {
                _logger.Here().Error(ex, "Cannot initialize node monitor service");
            }
    }

    public bool Start()
    {
        if (!_configuration.Enabled) return false;

        return true;
    }

    public void Stop()
    {
        if (!_configuration.Enabled || !_client.Connected) return;

        try
        {
            _client.Disconnect(true);
        }
        catch (Exception ex)
        {
            _logger.Here().Error(ex, "Error while stopping TCP listener");
        }
    }

    public async Task<bool> ConnectAsync(CancellationToken cancellationToken)
    {
        try
        {
            await _client.ConnectAsync(_endPoint, cancellationToken);
            _logger.Here().Information("Client connected: {@Connected}", _client.Connected);
        }
        catch (Exception ex)
        {
            _logger.Here().Error(ex, "Cannot connect to tester {@Address}:{@Port} ",
                _endPoint.Address.ToString(),
                _endPoint.Port);

            return false;
        }

        return true;
    }
}