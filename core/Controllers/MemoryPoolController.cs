// Tangram by Matthew Hellyer is licensed under CC BY-NC-ND 4.0.
// To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0

using System;
using System.Threading.Tasks;
using TangramXtgm.Extensions;
using TangramXtgm.Ledger;
using Dawn;
using MessagePack;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Serilog;
using TangramXtgm.Models;

namespace TangramXtgm.Controllers;

/// <summary>
/// Controller class for managing the memory pool.
/// </summary>
[Route("mempool")]
[ApiController]
public class MemoryPoolController : Controller
{
    private readonly ISystemCore _systemCore;
    private readonly ILogger _logger;

    /// <summary>
    /// Represents a controller for managing a memory pool.
    /// </summary>
    /// <param name="systemCore">The system core instance.</param>
    /// <param name="logger">The logger instance.</param>
    public MemoryPoolController(ISystemCore systemCore, ILogger logger)
    {
        _systemCore = systemCore;
        _logger = logger.ForContext("SourceContext", nameof(MemoryPoolController));
    }

    /// <summary>
    /// Creates a new transaction and adds it to the memory pool.
    /// </summary>
    /// <param name="data">The byte array representing the transaction data.</param>
    /// <returns>Returns an IActionResult representing the result of the operation.</returns>
    [HttpPost("transaction", Name = "NewTransaction")]
    [ProducesResponseType(typeof(bool), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<IActionResult> NewTransactionAsync([FromBody] byte[] data)
    {
        Guard.Argument(data, nameof(data)).NotNull().NotEmpty();
        try
        {
            var transaction = MessagePackSerializer.Deserialize<Transaction>(data);
            var added = await _systemCore.MemPool().NewTransactionAsync(transaction);
            return added switch
            {
                VerifyResult.Succeed => new ObjectResult(StatusCodes.Status200OK),
                VerifyResult.AlreadyExists => new ConflictObjectResult(StatusCodes.Status409Conflict),
                _ => new BadRequestObjectResult(StatusCodes.Status500InternalServerError)
            };
        }
        catch (Exception ex)
        {
            _logger.Here().Error(ex, "Unable to add the memory pool transaction");
        }

        return new StatusCodeResult(StatusCodes.Status500InternalServerError);
    }

    /// <summary>
    /// Retrieves a transaction from the memory pool or the Proof of Stake (PoS) transaction pool.
    /// </summary>
    /// <param name="id">The identifier of the transaction.</param>
    /// <returns>
    /// An IActionResult representing the result of the operation.
    /// If the transaction is found, the result contains the transaction data in binary format.
    /// If the transaction is not found, a status code 404 (Not Found) is returned.
    /// </returns>
    [HttpGet("transaction/{id}", Name = "GetMemoryPoolTransaction")]
    [ProducesResponseType(typeof(byte[]), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GetTransactionAsync(string id)
    {
        Guard.Argument(id, nameof(id)).NotNull().NotEmpty().NotWhiteSpace();
        try
        {
            var transaction = _systemCore.MemPool().Get(id.HexToByte());
            if (transaction is { })
                return new ObjectResult(new { transaction });

            transaction = _systemCore.PPoS().Get(id.HexToByte());
            if (transaction is { })
                return new ObjectResult(new { transaction });
        }
        catch (Exception ex)
        {
            _logger.Here().Error(ex, "Unable to get the memory pool transaction");
        }

        return NotFound();
    }

    /// <summary>
    /// Retrieves the total count of memory pool transactions and PPoS transactions.
    /// </summary>
    /// <returns>
    /// An integer representing the total count of memory pool transactions and PPoS transactions.
    /// </returns>
    /// <remarks>
    /// This method sends an HTTP GET request to the "count" endpoint to retrieve the count.
    /// If the count is successfully retrieved, the method returns an <see cref="ObjectResult"/>
    /// containing the count as a property of an anonymous object.
    /// If an error occurs while retrieving the count, a 500 Internal Server Error response
    /// is returned.</remarks>
    [HttpGet("count", Name = "GetCount")]
    [ProducesResponseType(typeof(int), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<IActionResult> GetCountAsync()
    {
        try
        {
            var memPoolCount = _systemCore.MemPool().Count();
            var pPoSCount = _systemCore.PPoS().Count();
            var total = memPoolCount + pPoSCount;
            return new ObjectResult(new { count = total });
        }
        catch (Exception ex)
        {
            _logger.Here().Error(ex, "Unable to get the memory pool transaction count");
        }

        return new StatusCodeResult(StatusCodes.Status500InternalServerError);
    }
}