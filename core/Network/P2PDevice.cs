// Tangram by Matthew Hellyer is licensed under CC BY-NC-ND 4.0.
// To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0

using System;
using System.Buffers;
using System.Collections.Generic;
using System.Net;
using System.Reactive.Linq;
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

namespace TangramXtgm.Network;

/// <summary>
/// 
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
/// 
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
/// 
/// </summary>
public enum Transport
{
    Tcp = 0x01,
    Ws = 0x02
}

/// <summary>
/// </summary>
public interface IP2PDevice
{
    Task<Message> DecryptAsync(INngMsg nngMsg);
}

/// <summary>
/// </summary>
public sealed class P2PDevice : IP2PDevice, IDisposable
{
    private readonly ISystemCore _systemCore;
    private readonly ILogger _logger;
    private readonly IList<IDisposable> _disposables = new List<IDisposable>();

    private IRepSocket _repSocket;
    private bool _disposed;

    /// <summary>
    /// </summary>
    /// <param name="systemCore"></param>
    public P2PDevice(ISystemCore systemCore)
    {
        _systemCore = systemCore;
        using var serviceScope = _systemCore.ServiceScopeFactory.CreateScope();
        _logger = serviceScope.ServiceProvider.GetService<ILogger>()?.ForContext("SourceContext", nameof(P2PDevice));
        Init();
    }

    /// <summary>
    /// </summary>
    /// <param name="nngMsg"></param>
    /// <returns></returns>
    public unsafe Task<Message> DecryptAsync(INngMsg nngMsg)
    {
        try
        {
            var msg = nngMsg.AsSpan();
            var length = BitConverter.ToInt32(msg);
            if (length != 32) return Task.FromResult(new Message(new Memory<byte>(), Array.Empty<byte>()));
            const int prefixByteLength = 4;
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
    /// </summary>
    private void Init()
    {
        Util.ThrowPortNotFree(_systemCore.Node.Network.P2P.TcpPort);
        _systemCore.Node.EndPoint.Port = _systemCore.Node.Network.P2P.TcpPort;
        ListeningAsync(new(Util.GetIpAddress(), _systemCore.Node.EndPoint.Port), Transport.Tcp, 5).ConfigureAwait(false);
        Util.ThrowPortNotFree(_systemCore.Node.Network.P2P.WsPort);
        _systemCore.Node.EndPoint.Port = _systemCore.Node.Network.P2P.WsPort;
        ListeningAsync(new(Util.GetIpAddress(), _systemCore.Node.EndPoint.Port), Transport.Ws, 1).ConfigureAwait(false);
    }

    /// <summary>
    /// 
    /// </summary>
    /// <returns></returns>
    private Task ListeningAsync(IPEndPoint ipEndPoint, Transport transport, int workerCount)
    {
        try
        {
            _repSocket = NngFactorySingleton.Instance.Factory.ReplierOpen()
                .ThenListen($"{GetTransportType(transport)}://{ipEndPoint.Address.ToString()}:{ipEndPoint.Port}", Defines.NngFlag.NNG_FLAG_NONBLOCK).Unwrap();
            _repSocket.SetOpt(Defines.NNG_OPT_RECVMAXSZ, 20000000);
            for (var i = 0; i < workerCount; i++)
            {
                var ctx = _repSocket.CreateAsyncContext(NngFactorySingleton.Instance.Factory).Unwrap();
                _disposables.Add(Observable.Interval(TimeSpan.Zero).Subscribe(_ =>
                {
                    if (_systemCore.ApplicationLifetime.ApplicationStopping.IsCancellationRequested) return;
                    try
                    {
                        WorkerAsync(ctx).Wait();
                    }
                    catch (AggregateException)
                    {
                        // Ignore
                    }
                }));
            }
        }
        catch (Exception ex)
        {
            _logger.Here().Error("{@Message}", ex.Message);
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="ctx"></param>
    private async Task WorkerAsync(IRepReqAsyncContext<INngMsg> ctx)
    {
        var nngResult = (await ctx.Receive()).Unwrap();
        try
        {
            var message = await _systemCore.P2PDevice().DecryptAsync(nngResult);
            if (message.Memory.Length == 0)
            {
                await EmptyReplyAsync(ctx);
                return;
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
                        return;
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

    /// <summary>
    /// 
    /// </summary>
    /// <param name="ctx"></param>
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
    /// 
    /// </summary>
    /// <param name="msg"></param>
    /// <returns></returns>
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
    /// 
    /// </summary>
    /// <param name="transport"></param>
    /// <returns></returns>
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
    /// 
    /// </summary>
    /// <param name="disposing"></param>
    private void Dispose(bool disposing)
    {
        if (_disposed)
        {
            return;
        }

        if (disposing)
        {
            _repSocket?.Dispose();
            foreach (var disposable in _disposables)
            {
                disposable.Dispose();
            }
        }

        _disposed = true;
    }

    /// <summary>
    /// 
    /// </summary>
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }
}