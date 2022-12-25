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

[Route("mempool")]
[ApiController]
public class MemoryPoolController : Controller
{
    private readonly ISystemCore _systemCore;
    private readonly ILogger _logger;

    /// <summary>
    /// </summary>
    /// <param name="systemCore"></param>
    /// <param name="logger"></param>
    public MemoryPoolController(ISystemCore systemCore, ILogger logger)
    {
        _systemCore = systemCore;
        _logger = logger.ForContext("SourceContext", nameof(MemoryPoolController));
    }

    /// <summary>
    /// </summary>
    /// <param name="data"></param>
    /// <returns></returns>
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
    /// </summary>
    /// <returns></returns>
    [HttpGet("transaction/{id}", Name = "GetMemoryPoolTransaction")]
    [ProducesResponseType(typeof(byte[]), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GetTransactionAsync(string id)
    {
        Guard.Argument(id, nameof(id)).NotNull().NotEmpty().NotWhiteSpace();
        try
        {
            var memPoolTransaction = _systemCore.MemPool().Get(id.HexToByte());
            if (memPoolTransaction is { })
                return new ObjectResult(new { memPoolTransaction });

            var pPosMemPoolTransaction = _systemCore.PPoS().Get(id.HexToByte());
            if (pPosMemPoolTransaction is { })
                return new ObjectResult(new { pPosMemPoolTransaction });
        }
        catch (Exception ex)
        {
            _logger.Here().Error(ex, "Unable to get the memory pool transaction");
        }

        return NotFound();
    }

    /// <summary>
    /// </summary>
    /// <returns></returns>
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