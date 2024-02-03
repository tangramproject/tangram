using System;
using System.IO;
using System.Net;
using System.Text;
using TangramXtgm.Extensions;

namespace TangramXtgm.Network.Mesh;

public static class StreamExtensions
{
    /// <summary>
    /// 
    /// </summary>
    /// <param name="stream"></param>
    /// <returns></returns>
    public static MessageType ReadMessageType(this Stream stream)
    {
        return (MessageType)stream.ReadByte();
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="stream"></param>
    /// <returns></returns>
    public static MemberState ReadMemberState(this Stream stream)
    {
        return (MemberState)stream.ReadByte();
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="stream"></param>
    /// <returns></returns>
    public static IPAddress ReadIPAddress(this Stream stream)
    {
        return new IPAddress(new[]
            { (byte)stream.ReadByte(), (byte)stream.ReadByte(), (byte)stream.ReadByte(), (byte)stream.ReadByte() });
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="stream"></param>
    /// <returns></returns>
    public static byte[] ReadPublicKey(this Stream stream)
    {
        var buffer = new byte[33];
        stream.Position = 9;
        using var ms = new MemoryStream();
        int read;
        while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
        {
            ms.Write(buffer, 0, read);
        }

        return ms.ToArray();
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="stream"></param>
    /// <returns></returns>
    public static byte[] ReadServiceName(this Stream stream)
    {
        if (!stream.CanSeek)
        {
            throw new NotSupportedException("The stream does not support seeking.");
        }
  
        stream.Position = 42;
        var buffer = new byte[32];
        using var ms = new MemoryStream();
        int read;
        while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
        {
            ms.Write(buffer, 0, read);
        }
  
        var bufferString = Encoding.UTF8.GetString(ms.ToArray());
        var index = bufferString.IndexOf('\0');
        if (index >= 0)
        {
            bufferString = bufferString[..index];
        }
  
        return Encoding.UTF8.GetBytes(bufferString);
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="stream"></param>
    /// <returns></returns>
    public static ushort ReadPort(this Stream stream)
    {
        var bigByte = (byte)stream.ReadByte();
        var littleByte = (byte)stream.ReadByte();

        return BitConverter.IsLittleEndian ?
         BitConverter.ToUInt16(new[] { littleByte, bigByte }, 0) :
         BitConverter.ToUInt16(new[] { bigByte, littleByte }, 0);
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="stream"></param>
    /// <returns></returns>
    public static ushort ReadService(this Stream stream)
    {
        var buffer = new byte[5];
        using var ms = new MemoryStream();
        int read;
        while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
        {
            ms.Write(buffer, 0, read);
        }
        return BitConverter.ToUInt16(ms.ToArray(), 0);
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="stream"></param>
    /// <returns></returns>
    public static IPEndPoint ReadIPEndPoint(this Stream stream)
    {
        return new IPEndPoint(stream.ReadIPAddress(), stream.ReadPort());
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="stream"></param>
    /// <param name="ipAddress"></param>
    /// <exception cref="ArgumentNullException"></exception>
    public static void WriteIPAddress(this Stream stream, IPAddress ipAddress)
    {
        if (ipAddress == null)
        {
            throw new ArgumentNullException(nameof(ipAddress));
        }

        stream.Write(ipAddress.GetAddressBytes(), 0, 4);
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="stream"></param>
    /// <param name="port"></param>
    public static void WritePort(this Stream stream, ushort port)
    {
        stream.WriteByte((byte)(port >> 8));
        stream.WriteByte((byte)port);
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="stream"></param>
    /// <param name="service"></param>
    public static void WriteService(this Stream stream, uint service)
    {
        stream.Write(service);
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="stream"></param>
    /// <param name="publicKey"></param>
    public static void WritePublicKey(this Stream stream, byte[] publicKey)
    {
        stream.Write(publicKey);
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="stream"></param>
    /// <param name="name"></param>
    public static void WriteServiceName(this Stream stream, byte[] name)
    {
        stream.Write(name);
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="stream"></param>
    /// <param name="version"></param>
    public static void WriteServiceVersion(this Stream stream, byte[] version)
    {
        stream.Write(version);
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="stream"></param>
    /// <param name="ipEndPoint"></param>
    /// <exception cref="ArgumentNullException"></exception>
    public static void WriteIPEndPoint(this Stream stream, IPEndPoint ipEndPoint)
    {
        if (ipEndPoint == null)
        {
            throw new ArgumentNullException(nameof(ipEndPoint));
        }

        stream.WriteIPAddress(ipEndPoint.Address);
        stream.WritePort((ushort)ipEndPoint.Port);
    }
}