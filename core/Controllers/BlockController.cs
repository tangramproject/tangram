// Tangram by Matthew Hellyer is licensed under CC BY-NC-ND 4.0.
// To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0

using System;
using System.Threading.Tasks;
using TangramXtgm.Extensions;
using Dawn;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Serilog;
using TangramXtgm.Models.Messages;

namespace TangramXtgm.Controllers;

/// <summary>
/// Controller class for managing blocks.
/// </summary>
[Route("chain")]
[ApiController]
public class BlockController : Controller
{
    private readonly ISystemCore _systemCore;
    private readonly ILogger _logger;

    /// <summary>
    /// This class represents a Block Controller.
    /// </summary>
    public BlockController(ISystemCore systemCore, ILogger logger)
    {
        _systemCore = systemCore;
        _logger = logger.ForContext("SourceContext", nameof(BlockController));
    }

    /// <summary>
    /// Retrieves the supply information.
    /// </summary>
    /// <returns>
    /// Returns an HTTP response with the supply information in the body if successful (HTTP 200 OK).
    /// If unable to retrieve the supply information, returns an HTTP response with status code 404 (Not Found).
    /// </returns>
    [HttpGet("supply", Name = "GetSupply")]
    [ProducesResponseType(typeof(byte[]), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GetSupply()
    {
        try
        {
            var distribution = await _systemCore.Validator().RunningDistributionAsync();
            return new ObjectResult(new { distribution });
        }
        catch (Exception ex)
        {
            _logger.Here().Error(ex, "Unable to get the supply");
        }

        return NotFound();
    }

    /// <summary>
    /// Retrieves a block asynchronously based on the provided hash.
    /// </summary>
    /// <param name="hash">The hash of the block to retrieve.</param>
    /// <returns>Returns an IActionResult representing the result of the operation. If the block is found, a 200 OK response will be returned along with the block data. If the block is not found, a 404 Not Found response will be returned.</returns>
    [HttpGet("block", Name = "GetBlock")]
    [ProducesResponseType(typeof(byte[]), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GetBlockAsync(string hash)
    {
        try
        {
            var blockResponse =
                await _systemCore.Graph().GetBlockAsync(new BlockRequest(hash.HexToByte()));
            if (blockResponse?.Block is { }) return new ObjectResult(new { blockResponse.Block });
        }
        catch (Exception ex)
        {
            _logger.Here().Error(ex, "Unable to get the block");
        }

        return NotFound();
    }

    /// <summary>
    /// Retrieves a collection of blocks asynchronously.
    /// </summary>
    /// <param name="skip">The number of blocks to skip.</param>
    /// <param name="take">The number of blocks to take.</param>
    /// <returns>An asynchronous operation that represents the HTTP response of the blocks collection.</returns>
    [HttpGet("blocks/{skip}/{take}", Name = "GetBlocks")]
    [ProducesResponseType(typeof(byte[]), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GetBlocksAsync(int skip, int take)
    {
        Guard.Argument(skip, nameof(skip)).NotNegative();
        Guard.Argument(take, nameof(take)).NotNegative();
        try
        {
            var blocksResponse =
                await _systemCore.Graph().GetBlocksAsync(new BlocksRequest(skip, take));
            return new ObjectResult(new { blocksResponse?.Blocks });
        }
        catch (Exception ex)
        {
            _logger.Here().Error(ex, "Unable to get blocks");
        }

        return NotFound();
    }

    /// <summary>
    /// Retrieves a block from the blockchain by its height.
    /// </summary>
    /// <param name="height">The height of the block to retrieve.</param>
    /// <returns>Returns an IActionResult representing the block if found, otherwise returns NotFound().</returns>
    [HttpGet("block/{height}", Name = "GetBlockByHeight")]
    [ProducesResponseType(typeof(byte[]), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GetBlockByHeightAsync(ulong height)
    {
        try
        {
            var blockResponse =
                await _systemCore.Graph().GetBlockByHeightAsync(new BlockByHeightRequest(height));
            if (blockResponse?.Block is { }) return new ObjectResult(new { blockResponse.Block });
        }
        catch (Exception ex)
        {
            _logger.Here().Error(ex, "Unable to get the block");
        }

        return NotFound();
    }

    /// <summary>
    /// Retrieves the transaction block by hash.
    /// </summary>
    /// <param name="hash">The hash of the transaction.</param>
    /// <returns>
    /// Returns an <see cref="IActionResult"/> representing the result of the asynchronous operation.
    /// The result contains the transaction block as a byte array wrapped in an <see cref="ObjectResult"/>.
    /// If the transaction block is found, the HTTP status code of the response will be 200 (OK).
    /// If the transaction block is not found, the HTTP status code of the response will be 404 (Not Found).
    /// </returns>
    [HttpGet("block/transaction/{hash}", Name = "GetTransactionBlock")]
    [ProducesResponseType(typeof(byte[]), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GetTransactionBlockAsync(string hash)
    {
        Guard.Argument(hash, nameof(hash)).NotNull().NotEmpty().NotWhiteSpace();
        try
        {
            var transactionBlock =
                await _systemCore.Graph().GetTransactionBlockAsync(
                    new TransactionIdRequest(hash.HexToByte()));
            return new ObjectResult(new { transactionBlock?.Block });
        }
        catch (Exception ex)
        {
            _logger.Here().Error(ex, "Unable to get the transaction");
        }

        return NotFound();
    }

    /// <summary>
    /// Retrieves the height of the blockchain.
    /// </summary>
    /// <returns>
    /// An <see cref="IActionResult"/> object that represents the result of the action.
    /// If the height is successfully retrieved, the <see cref="IActionResult"/> object will have a status code of 200 (OK)
    /// and the height value will be included in the response body.
    /// If the height cannot be retrieved, the <see cref="IActionResult"/> object will have a status code of 404 (Not Found).
    /// </returns>
    [HttpGet("height", Name = "GetBlockHeight")]
    [ProducesResponseType(typeof(long), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GetBlockHeightAsync()
    {
        try
        {
            return new ObjectResult(new { height = _systemCore.UnitOfWork().HashChainRepository.Count });
        }
        catch (Exception ex)
        {
            _logger.Here().Error(ex, "Unable to get the block height");
        }

        return NotFound();
    }

    /// <summary>
    /// Retrieves a transaction with the given hash.
    /// </summary>
    /// <param name="hash">The hash of the transaction.</param>
    /// <returns>The transaction identified by the given hash.</returns>
    /// <remarks>
    /// Returns a 404 NotFound if the transaction is not found.
    /// </remarks>
    [HttpGet("transaction/{hash}", Name = "GetTransaction")]
    [ProducesResponseType(typeof(byte[]), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GetTransactionAsync(string hash)
    {
        Guard.Argument(hash, nameof(hash)).NotNull().NotEmpty().NotWhiteSpace();
        try
        {
            var transactionResponse =
                await _systemCore.Graph().GetTransactionAsync(new TransactionRequest(hash.HexToByte()));
            return new ObjectResult(new { transactionResponse?.Transaction });
        }
        catch (Exception ex)
        {
            _logger.Here().Error(ex, "Unable to get the transaction");
        }

        return NotFound();
    }

    /// <summary>
    /// Retrieves safeguard blocks asynchronously.
    /// </summary>
    /// <returns>A <see cref="Task{TResult}"/> representing the asynchronous operation. The task result contains an <see cref="IActionResult"/>.</returns>
    [HttpGet("safeguards", Name = "GetSafeguardBlocks")]
    [ProducesResponseType(typeof(byte[]), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GetSafeguardBlocksAsync()
    {
        try
        {
            var safeguardBlocksResponse =
                await _systemCore.Graph().GetSafeguardBlocksAsync(new SafeguardBlocksRequest(147));
            return new ObjectResult(new { safeguardBlocksResponse?.Blocks });
        }
        catch (Exception ex)
        {
            _logger.Here().Error(ex, "Unable to get safeguard blocks");
        }

        return NotFound();
    }

    /// <summary>
    /// Retrieves the running distribution value.
    /// </summary>
    /// <returns>
    /// Returns an <see cref="IActionResult"/> representing the result of the operation.
    /// If the operation is successful, the status code is <see cref="StatusCodes.Status200OK"/> and
    /// the running distribution value is returned.
    /// If the operation fails due to an exception, the status code is <see cref="StatusCodes.Status404NotFound"/>.
    /// </returns>
    [HttpGet("emission", Name = "GetRunningDistribution")]
    [ProducesResponseType(typeof(long), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GetRunningDistributionAsync()
    {
        try
        {
            var distribution = await _systemCore.Validator().RunningDistributionAsync();
            return new ObjectResult(new { emission = Ledger.LedgerConstant.Distribution - distribution });
        }
        catch (Exception ex)
        {
            _logger.Here().Error(ex, "Unable to get the emission");
        }

        return NotFound();
    }
}