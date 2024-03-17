// Tangram by Matthew Hellyer is licensed under CC BY-NC-ND 4.0.
// To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0

using System;
using System.Linq;
using System.Threading.Tasks;
using TangramXtgm.Extensions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Serilog;
using TangramXtgm.Models;

namespace TangramXtgm.Controllers;

/// <summary>
/// Controller that handles membership-related operations.
/// </summary>
[Route("member")]
[ApiController]
public class MembershipController : Controller
{
    private readonly ISystemCore _systemCore;
    private readonly ILogger _logger;

    /// <summary>
    /// Initializes a new instance of the MembershipController class.
    /// </summary>
    /// <param name="systemCore">An instance of ISystemCore that provides access to system core functionalities.</param>
    /// <param name="logger">An instance of ILogger used for logging.</param>
    public MembershipController(ISystemCore systemCore, ILogger logger)
    {
        _systemCore = systemCore;
        _logger = logger.ForContext("SourceContext", nameof(MembershipController));
    }

    /// <summary>
    /// Retrieves information about the local peer.
    /// </summary>
    /// <returns>An IActionResult with the information of the local peer if found, otherwise returns NotFound.</returns>
    [HttpGet("peer", Name = "GetPeer")]
    [ProducesResponseType(typeof(byte[]), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GetPeerAsync()
    {
        try
        {
            var peer = _systemCore.PeerDiscovery().GetLocalNode();
            return new ObjectResult(new
            {
                IPAddress = peer.IpAddress.FromBytes(),
                peer.NodeId,
                HttpPort = peer.HttpPort.FromBytes(),
                HttpsPort = peer.HttpsPort.FromBytes(),
                TcpPort = peer.TcpPort.FromBytes(),
                WsPort = peer.WsPort.FromBytes(),
                Name = peer.Name.FromBytes(),
                PublicKey = peer.PublicKey.ByteToHex(),
                Version = peer.Version.FromBytes()
            });
        }
        catch (Exception ex)
        {
            _logger.Here().Error("{Message}", ex.Message);
        }

        return NotFound();
    }

    /// <summary>
    /// Retrieves the peers available in the system.
    /// </summary>
    /// <returns>A collection of peers containing their IP address, node ID, service port, name, and public key.</returns>
    [HttpGet("peers", Name = "GetPeers")]
    [ProducesResponseType(typeof(byte[]), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GetPeersAsync()
    {
        try
        {
            var peers = _systemCore.PeerDiscovery().GetPeerStore();
            return new ObjectResult(peers.Select(peer => new
            {
                IPAddress = peer.IpAddress.FromBytes(),
                peer.NodeId,
                ServicePort = peer.TcpPort.FromBytes(),
                Name = peer.Name.FromBytes(),
                PublicKey = peer.PublicKey.ByteToHex(),
                State = Peer.GetPeerStateDescription(peer.PeerState),
                Version = peer.Version.FromBytes()
            }));
        }
        catch (Exception ex)
        {
            _logger.Here().Error("{Message}", ex.Message);
        }

        return NotFound();
    }

    /// <summary>
    /// Retrieves the count of peers from the PeerDiscovery system.
    /// </summary>
    /// <remarks>
    /// This method sends an HTTP GET request to the "count" endpoint
    /// in order to retrieve the current count of peers from the PeerDiscovery system.
    /// </remarks>
    /// <returns>
    /// An IActionResult representing the result of the request.
    /// </returns>
    /// <response code="200">Returns the count of peers as a byte array.</response>
    /// <response code="404">If the count of peers could not be found.</response>
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