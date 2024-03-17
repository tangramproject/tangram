// Tangram by Matthew Hellyer is licensed under CC BY-NC-ND 4.0.
// To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0

using System;
using System.Buffers;
using System.Net;
using System.Threading.Tasks;
using TangramXtgm.Extensions;
using MessagePack;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IO;
using nng;
using nng.Native;
using Serilog;
using TangramXtgm.Helper;
using TangramXtgm.Models;
using TangramXtgm.Models.Messages;
using System.Text;

namespace TangramXtgm.Network;

/// <summary>
/// Represents a message object.
/// </summary>
public struct Message
{
    public Memory<byte> Memory { get; }
    public byte[] PublicKey { get; }

    public Message(Memory<byte> memory, byte[] publicKey)
    {
        Memory = memory;
        PublicKey = publicKey;
    }
}

/// <summary>
/// Represents an unwrap message containing parameters and a protocol command.
/// </summary>
public struct UnwrapMessage
{
    public Parameter[] Parameters { get; }
    public ProtocolCommand ProtocolCommand { get; }

    public UnwrapMessage(Parameter[] parameters, ProtocolCommand protocolCommand)
    {
        Parameters = parameters;
        ProtocolCommand = protocolCommand;
    }
}

/// <summary>
/// Enum representing different types of transports.
/// </summary>
public enum Transport
{
    Tcp = 0x01,
    Ws = 0x02
}

/// <summary>
/// Represents a P2P device that can decrypt messages asynchronously.
/// </summary>
public interface IP2PDevice
{
    Task<Message> DecryptAsync(INngMsg nngMsg);
}

/// <summary>
/// Represents a peer-to-peer device.
/// </summary>
public sealed class P2PDevice : IP2PDevice, IDisposable
{
    private readonly ISystemCore _systemCore;
    private readonly ILogger _logger;

    private IRepSocket _repSocket;
    private bool _disposed;

    /// <summary>
    /// Represents a P2P (peer-to-peer) device.
    /// </summary>
    /// <param name="systemCore">The system core instance.</param>
    public P2PDevice(ISystemCore systemCore)
    {
        _systemCore = systemCore;
        using var serviceScope = _systemCore.ServiceScopeFactory.CreateScope();
        _logger = serviceScope.ServiceProvider.GetService<ILogger>()?.ForContext("SourceContext", nameof(P2PDevice));
        Init();
    }

    /// <summary>
    /// Decrypts an INngMsg asynchronously.
    /// </summary>
    /// <param name="nngMsg">The INngMsg to decrypt.</param>
    /// <returns>A Task representing the asynchronous decryption operation. The decrypted Message is returned.</returns>
    public unsafe Task<Message> DecryptAsync(INngMsg nngMsg)
    {
        const int prefixByteLength = 4;

        try
        {
            var msg = nngMsg.AsSpan();
            var length = BitConverter.ToInt32(msg);
            if (length != 32) return Task.FromResult(new Message(new Memory<byte>(), Array.Empty<byte>()));
            var pk = stackalloc byte[length];
            var publicKey = new Span<byte>(pk, length);
            msg.Slice(prefixByteLength, length).CopyTo(publicKey);
            length = BitConverter.ToInt32(msg[(prefixByteLength + publicKey.Length)..]);
            ReadOnlySpan<byte> cipher = msg[(prefixByteLength + publicKey.Length + prefixByteLength)..];
            if (cipher.Length != length) return Task.FromResult(new Message(new Memory<byte>(), Array.Empty<byte>()));
            var result = _systemCore.Crypto().BoxSealOpen(cipher,
                _systemCore.KeyPair.PrivateKey.FromSecureString().HexToByte(),
                _systemCore.KeyPair.PublicKey.AsSpan()[1..33]);
            var message = new Message(result, publicKey.ToArray());
            return Task.FromResult(message);
        }
        catch
        {
            // ignored
        }

        return Task.FromResult(new Message(new Memory<byte>(), Array.Empty<byte>()));
    }

    /// <summary>
    /// Initialize the system by setting up network ports and starting listening
    /// </summary>
    private void Init()
    {
        Util.ThrowPortNotFree(_systemCore.Node.Network.P2P.TcpPort);
        _systemCore.Node.EndPoint.Port = _systemCore.Node.Network.P2P.TcpPort;
        ListeningAsync(new(Util.GetIpAddress(), _systemCore.Node.EndPoint.Port), Transport.Tcp, 3).ConfigureAwait(false);
        Util.ThrowPortNotFree(_systemCore.Node.Network.P2P.WsPort);
        _systemCore.Node.EndPoint.Port = _systemCore.Node.Network.P2P.WsPort;
        ListeningAsync(new(Util.GetIpAddress(), _systemCore.Node.EndPoint.Port), Transport.Ws, 1).ConfigureAwait(false);
    }

    /// <summary>
    /// Starts listening on the specified IP endpoint for incoming requests using the given transport and worker count.
    /// </summary>
    /// <param name="ipEndPoint">The IP endpoint to listen on.</param>
    /// <param name="transport">The transport to use for communication.</param>
    /// <param name="workerCount">The number of worker threads to use for handling requests.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    private async Task ListeningAsync(IPEndPoint ipEndPoint, Transport transport, int workerCount)
    {
        try
        {
            _repSocket = NngFactorySingleton.Instance.Factory.ReplierOpen()
                .ThenListen($"{GetTransportType(transport)}://{ipEndPoint.Address}:{ipEndPoint.Port}", Defines.NngFlag.NNG_FLAG_NONBLOCK).Unwrap();
            _repSocket.SetOpt(Defines.NNG_OPT_RECVMAXSZ, 20000000);
            for (var i = 0; i < workerCount; i++)
            {
                await Task.Run(async () =>
                {
                    if (_systemCore.ApplicationLifetime.ApplicationStopping.IsCancellationRequested) return;
                    try
                    {
                        var ctx = _repSocket.CreateAsyncContext(NngFactorySingleton.Instance.Factory).Unwrap();
                        await WorkerAsync(ctx);
                    }
                    catch (Exception ex)
                    {
                        _logger.Here().Error("{@Message}", ex.Message);
                    }
                });
            }
        }
        catch (Exception ex)
        {
            _logger.Here().Error("{@Message}", ex.Message);
        }
    }

    /// <summary>
    /// Worker method that performs an asynchronous operation.
    /// </summary>
    /// <param name="ctx">The IRepReqAsyncContext&lt;INngMsg&gt; context used for receiving and replying to messages.</param>
    /// <returns>A Task representing the asynchronous operation.</returns>
    private async Task WorkerAsync(IRepReqAsyncContext<INngMsg> ctx)
    {
        while (!_systemCore.ApplicationLifetime.ApplicationStopping.IsCancellationRequested)
        {
            var nngResult = (await ctx.Receive()).Unwrap();
            try
            {
                if(IsHandshakeInitiationMessage(nngResult))
                {
                    await HandshakeInitiationReplyAsync(ctx);
                    continue;
                }

                var message = await _systemCore.P2PDevice().DecryptAsync(nngResult);
                if (message.Memory.Length == 0)
                {
                    await EmptyReplyAsync(ctx);
                    continue;
                }

                var unwrapMessage = await UnWrapAsync(message.Memory);
                if (unwrapMessage.ProtocolCommand != ProtocolCommand.NotFound)
                {
                    try
                    {
                        var newMsg = NngFactorySingleton.Instance.Factory.CreateMessage();
                        var readOnlySequence =
                            await _systemCore.P2PDeviceApi().Commands[(int)unwrapMessage.ProtocolCommand](
                                unwrapMessage.Parameters);

                        var cipher = _systemCore.Crypto().BoxSeal(
                            readOnlySequence.IsSingleSegment ? readOnlySequence.First.Span : readOnlySequence.ToArray(),
                            message.PublicKey);
                        if (cipher.Length != 0)
                        {
                            await using var packetStream = Util.Manager.GetStream() as RecyclableMemoryStream;
                            packetStream.Write(_systemCore.KeyPair.PublicKey[1..33].WrapLengthPrefix());
                            packetStream.Write(cipher.WrapLengthPrefix());
                            foreach (var memory in packetStream.GetReadOnlySequence()) newMsg.Append(memory.Span);
                            (await ctx.Reply(newMsg)).Unwrap();
                            newMsg.Dispose();
                            continue;
                        }
                    }
                    catch (MessagePackSerializationException)
                    {
                        // Ignore
                    }
                    catch (AccessViolationException ex)
                    {
                        _logger.Here().Fatal("{@Message}", ex.Message);
                    }
                    catch (Exception ex)
                    {
                        _logger.Here().Fatal("{@Message}", ex.Message);
                    }
                }

                await EmptyReplyAsync(ctx);
            }
            finally
            {
                nngResult.Dispose();
            }
        }
    }

    /// <summary>
    /// Replies to a handshake initiation request with the appropriate response.
    /// </summary>
    /// <param name="ctx">The asynchronous context for request and reply handling.</param>
    private async Task HandshakeInitiationReplyAsync(IRepReqAsyncContext<INngMsg> ctx)
    {
        try
        {
            // Create a new NNG message for the reply
            var newMsg = NngFactorySingleton.Instance.Factory.CreateMessage();

            // Prepare the handshake initiation response and write it to the packetStream
            await using var packetStream = Util.Manager.GetStream() as RecyclableMemoryStream;
            packetStream.Write((await _systemCore.P2PDeviceApi().Commands[(int)ProtocolCommand.HandshakeInitiation](null)).First.Span);

            // Append the content of the packetStream to the reply message
            foreach (var memory in packetStream.GetReadOnlySequence()) newMsg.Append(memory.Span);

            // Send the reply message
            (await ctx.Reply(newMsg)).Unwrap();
        }
        catch (Exception)
        {
            // Ignore any exceptions during the reply process
        }
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="nngMsg"></param>
    /// <returns></returns>
    private static bool IsHandshakeInitiationMessage(INngMsg nngMsg)
    {
        if (nngMsg.Length == 19)
        {
            var handshake = Encoding.ASCII.GetString(nngMsg.AsSpan());
            if (ProtocolCommand.HandshakeInitiation.ToString() == handshake)
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Sends an empty reply to the request context.
    /// </summary>
    /// <param name="ctx">The request context to reply to.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    private static async Task EmptyReplyAsync(IRepReqAsyncContext<INngMsg> ctx)
    {
        try
        {
            var newMsg = NngFactorySingleton.Instance.Factory.CreateMessage();
            (await ctx.Reply(newMsg)).Unwrap();
        }
        catch (Exception)
        {
            // Ignore
        }
    }

    /// <summary>
    /// Unwraps a message and returns the unwrapped message as an asynchronous operation.
    /// </summary>
    /// <param name="msg">The message to unwrap.</param>
    /// <returns>The unwrapped message as an <see cref="UnwrapMessage"/> object.</returns>
    private static async Task<UnwrapMessage> UnWrapAsync(ReadOnlyMemory<byte> msg)
    {
        try
        {
            await using var stream = Util.Manager.GetStream(msg.Span) as RecyclableMemoryStream;
            var parameters = await MessagePackSerializer.DeserializeAsync<Parameter[]>(stream);
            if (Enum.TryParse(Enum.GetName(parameters[0].ProtocolCommand), out ProtocolCommand command))
            {
                return new UnwrapMessage(parameters, command);
            }
        }
        catch (ArgumentOutOfRangeException ex)
        {
            Console.WriteLine("ArgumentOutOfRangeException: " + ex.Message);
        }
        catch (Exception ex)
        {
            Console.WriteLine("Exception: " + ex);
        }

        return default;
    }

    /// <summary>
    /// Returns the transport type based on the provided Transport enum value.
    /// </summary>
    /// <param name="transport">The Transport enum value to determine the transport type.</param>
    /// <returns>A string representing the transport type. Possible values are "tcp", "ws", or "tcp" if the provided transport is not recognized.</returns>
    private static string GetTransportType(Transport transport)
    {
        return transport switch
        {
            Transport.Tcp => "tcp",
            Transport.Ws => "ws",
            _ => "tcp"
        };
    }

    /// <summary>
    /// Disposes of resources used by the object.
    /// </summary>
    /// <param name="disposing">True if called from Dispose(), false if called from a finalizer.</param>
    private void Dispose(bool disposing)
    {
        if (_disposed)
        {
            return;
        }

        if (disposing)
        {
            _repSocket?.Dispose();
        }

        _disposed = true;
    }

    /// <summary>
    /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
    /// </summary>
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }
}