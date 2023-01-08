// Tangram by Matthew Hellyer is licensed under CC BY-NC-ND 4.0.
// To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0

using System;
using System.Diagnostics;
using System.Numerics;
using System.Threading;
using System.Threading.Tasks;
using TangramXtgm.Helper;

namespace TangramXtgm.Cryptography;

public enum PrimeBit : sbyte
{
    P256 = 0x00,
    P512 = 0x01,
    P1024 = 0x02
}

/// <summary>
/// </summary>
public class Sloth
{
    private const string PrimeBit1024 =
        "26665316952145251691159678627219217222885850903741016853585447718947343212288750750268012668712469908106258613976547496870890438504017231007766799519535785905104605162203896873810538315838185502276890025696087480171103337359532995917850779890238106057070346163136946293278160601772800244012833993583077700483";
    private const string PrimeBit512 =
        "1428747867218506432894623188342974573745986827958686951828141301796511703204477877094047850395093527438571991358833787830431256534283107665764428020239091";
    private const string PrimeBit256 =
        "60464814417085833675395020742168312237934553084050601624605007846337253615407";

    private readonly int _runForMs;
    private readonly CancellationToken _stoppingToken;
    private readonly PrimeBit _primeBit;

    /// <summary>
    /// </summary>
    /// <param name="runForMs"></param>
    /// <param name="stoppingToken"></param>
    public Sloth(PrimeBit primeBit, int runForMs, CancellationToken stoppingToken)
    {
        _primeBit = primeBit;
        _runForMs = runForMs;
        _stoppingToken = stoppingToken;
    }

    /// <summary>
    /// </summary>
    /// <param name="t"></param>
    /// <param name="x"></param>
    /// <returns></returns>
    public async Task<string> EvalAsync(int t, BigInteger x)
    {
        var p = BigInteger.Parse(GetPrimeBit(_primeBit));
        var y = await ModSqrtOpAsync(t, x, p);
        return y == BigInteger.Zero ? string.Empty : y.ToString();
    }

    /// <summary>
    /// </summary>
    /// <param name="t"></param>
    /// <param name="x"></param>
    /// <param name="y"></param>
    /// <returns></returns>
    public bool Verify(uint t, BigInteger x, BigInteger y)
    {
        var p = BigInteger.Parse(GetPrimeBit(_primeBit));
        if (!IsQuadraticResidue(x, p)) x = Util.Mod(BigInteger.Negate(x), p);
        for (var i = 0; i < t; i++) y = Square(y, p);

        return x.CompareTo(y) == 0;
    }

    /// <summary>
    /// </summary>
    /// <param name="value"></param>
    /// <param name="exponent"></param>
    /// <param name="modulus"></param>
    /// <returns></returns>
    private BigInteger ModExp(BigInteger value, BigInteger exponent, BigInteger modulus)
    {
        return BigInteger.ModPow(value, exponent, modulus);
    }

    /// <summary>
    /// </summary>
    /// <param name="x"></param>
    /// <param name="p"></param>
    /// <returns></returns>
    private bool IsQuadraticResidue(BigInteger x, BigInteger p)
    {
        var t = ModExp(x, Div(Sub(p, new BigInteger(1)), new BigInteger(2)), p);
        return t.CompareTo(new BigInteger(1)) == 0;
    }


    /// <summary>
    /// </summary>
    /// <param name="x"></param>
    /// <param name="y"></param>
    /// <returns></returns>
    private static BigInteger Add(BigInteger x, BigInteger y)
    {
        return BigInteger.Add(x, y);
    }

    /// <summary>
    /// </summary>
    /// <param name="x"></param>
    /// <param name="y"></param>
    /// <returns></returns>
    private static BigInteger Sub(BigInteger x, BigInteger y)
    {
        return BigInteger.Subtract(x, y);
    }

    /// <summary>
    /// </summary>
    /// <param name="x"></param>
    /// <param name="y"></param>
    /// <returns></returns>
    private static BigInteger Div(BigInteger x, BigInteger y)
    {
        return BigInteger.Divide(x, y);
    }

    /// <summary>
    /// </summary>
    /// <param name="x"></param>
    /// <param name="p"></param>
    /// <returns></returns>
    private BigInteger ModSqrt(BigInteger x, BigInteger p)
    {
        BigInteger y;
        if (IsQuadraticResidue(x, p))
        {
            y = ModExp(x, Div(Add(p, new BigInteger(1)), new BigInteger(4)), p);
        }
        else
        {
            x = Util.Mod(BigInteger.Negate(x), p);
            y = ModExp(x, Div(Add(p, new BigInteger(1)), new BigInteger(4)), p);
        }

        return y;
    }

    /// <summary>
    /// </summary>
    /// <param name="y"></param>
    /// <param name="p"></param>
    /// <returns></returns>
    private BigInteger Square(BigInteger y, BigInteger p)
    {
        return ModExp(y, new BigInteger(2), p);
    }

    /// <summary>
    /// </summary>
    /// <param name="t"></param>
    /// <param name="x"></param>
    /// <param name="p"></param>
    /// <returns></returns>
    private async Task<BigInteger> ModSqrtOpAsync(int t, BigInteger x, BigInteger p)
    {
        return await Task.Factory.StartNew(() =>
        {
            var sw = new Stopwatch();
            var y = new BigInteger(0);
            y = x;
            sw.Start();
            try
            {
                for (var i = 0; i < t; i++)
                {
                    if (sw.ElapsedMilliseconds > _runForMs)
                    {
                        y = BigInteger.Zero;
                        break;
                    }

                    if (_stoppingToken.IsCancellationRequested)
                    {
                        y = BigInteger.Zero;
                        break;
                    }

                    y = ModSqrt(y, p);
                }

                return y;
            }
            finally
            {
                sw.Stop();
            }
        }, TaskCreationOptions.LongRunning).ConfigureAwait(false);
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="primeBit"></param>
    /// <returns></returns>
    /// <exception cref="ArgumentOutOfRangeException"></exception>
    private static string GetPrimeBit(PrimeBit primeBit)
    {
        return primeBit switch
        {
            PrimeBit.P256 => PrimeBit256,
            PrimeBit.P512 => PrimeBit512,
            PrimeBit.P1024 => PrimeBit1024,
            _ => throw new ArgumentOutOfRangeException(nameof(primeBit), primeBit, null)
        };
    }
}