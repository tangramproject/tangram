// Tangram by Matthew Hellyer is licensed under CC BY-NC-ND 4.0.
// To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0

using System;
using System.Linq;
using System.Threading.Tasks;
using TangramXtgm.Extensions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Serilog;

namespace TangramXtgm.Controllers;

[Route("member")]
[ApiController]
public class MembershipController : Controller
{
    private readonly ISystemCore _systemCore;
    private readonly ILogger _logger;

    /// <summary>
    /// </summary>
    /// <param name="systemCore"></param>
    /// <param name="logger"></param>
    public MembershipController(ISystemCore systemCore, ILogger logger)
    {
        _systemCore = systemCore;
        _logger = logger.ForContext("SourceContext", nameof(MembershipController));
    }

    /// <summary>
    /// </summary>
    /// <returns></returns>
    [HttpGet("peer", Name = "GetPeer")]
    [ProducesResponseType(typeof(byte[]), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GetPeerAsync()
    {
        try
        {
            var peer = _systemCore.PeerDiscovery().GetLocalPeer();
            return new ObjectResult(new
            {
                IPAddress = peer.IpAddress.FromBytes(),
                BlockHeight = peer.BlockCount,
                peer.ClientId,
                HttpPort = peer.HttpPort.FromBytes(),
                HttpsPort = peer.HttpsPort.FromBytes(),
                TcpPort = peer.TcpPort.FromBytes(),
                WsPort = peer.WsPort.FromBytes(),
                DsPort = peer.DsPort.FromBytes(),
                Name = peer.Name.FromBytes(),
                PublicKey = peer.PublicKey.ByteToHex(),
                Version = peer.Version.FromBytes()
            });
        }
        catch (Exception ex)
        {
            _logger.Here().Error(ex.Message);
        }

        return NotFound();
    }

    /// <summary>
    /// </summary>
    /// <returns></returns>
    [HttpGet("peers", Name = "GetPeers")]
    [ProducesResponseType(typeof(byte[]), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GetPeersAsync()
    {
        try
        {
            var peers = await _systemCore.PeerDiscovery().GetDiscoveryAsync();
            return new ObjectResult(peers.Select(peer => new
            {
                IPAddress = peer.IpAddress.FromBytes(),
                BlockHeight = peer.BlockCount,
                peer.ClientId,
                HttpPort = peer.HttpPort.FromBytes(),
                HttpsPort = peer.HttpsPort.FromBytes(),
                TcpPort = peer.TcpPort.FromBytes(),
                WsPort = peer.WsPort.FromBytes(),
                DsPort = peer.DsPort.FromBytes(),
                Name = peer.Name.FromBytes(),
                PublicKey = peer.PublicKey.ByteToHex(),
                Version = peer.Version.FromBytes()
            }));
        }
        catch (Exception ex)
        {
            _logger.Here().Error(ex.Message);
        }

        return NotFound();
    }

    /// <summary>
    /// </summary>
    /// <returns></returns>
    [HttpGet("count", Name = "GetPeersCount")]
    [ProducesResponseType(typeof(byte[]), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GetPeersCountAsync()
    {
        try
        {
            return new ObjectResult(new { count = _systemCore.PeerDiscovery().Count() });
        }
        catch (Exception ex)
        {
            _logger.Here().Error("{@Message}", ex.Message);
        }

        return NotFound();
    }
}