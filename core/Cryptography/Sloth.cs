// Tangram by Matthew Hellyer is licensed under CC BY-NC-ND 4.0.
// To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0

using System;
using System.Diagnostics;
using System.Numerics;
using System.Threading;
using System.Threading.Tasks;
using Dawn;
using TangramXtgm.Helper;

namespace TangramXtgm.Cryptography;

public enum PrimeBit : sbyte
{
    P256 = 0x00,
    P512 = 0x01,
    P1024 = 0x02
}

/// <summary>
/// Represents a Sloth algorithm implementation.
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
    /// Represents a class that performs a sloth operation.
    /// </summary>
    /// <param name="primeBit">A PrimeBit object that represents the specific prime bit used in the operation.</param>
    /// <param name="runForMs">An integer that specifies the duration of the sloth operation in milliseconds.</param>
    /// <param name="stoppingToken">A CancellationToken object that can be used to request cancellation of the sloth operation.</param>
    public Sloth(PrimeBit primeBit, int runForMs, CancellationToken stoppingToken)
    {
        Guard.Argument(runForMs, nameof(runForMs)).NotNegative().NotZero();
        _primeBit = primeBit;
        _runForMs = runForMs;
        _stoppingToken = stoppingToken;
    }

    /// <summary>
    /// Evaluates the square root of a given integer 'x' modulo a prime number, 'p', and returns the result as a string.
    /// </summary>
    /// <param name="t">The integer t.</param>
    /// <param name="x">The BigInteger x.</param>
    /// <returns>The square root of x modulo p as a string. An empty string is returned if the result is zero.</returns>
    public async Task<string> EvalAsync(int t, BigInteger x)
    {
        Guard.Argument(t, nameof(t)).NotNegative().NotZero();
        var p = BigInteger.Parse(GetPrimeBit(_primeBit));
        var y = await ModSqrtOpAsync(t, x, p);
        return y == BigInteger.Zero ? string.Empty : y.ToString();
    }

    /// <summary>
    /// Verifies if two BigIntegers x and y are equal after performing t iterations of a square operation.
    /// </summary>
    /// <param name="t">The number of iterations</param>
    /// <param name="x">The first BigInteger</param>
    /// <param name="y">The second BigInteger</param>
    /// <returns>True if x is equal to y after performing t iterations of the square operation, otherwise false.</returns>
    public bool Verify(uint t, BigInteger x, BigInteger y)
    {
        Guard.Argument(t, nameof(t)).NotZero();
        var p = BigInteger.Parse(GetPrimeBit(_primeBit));
        if (!IsQuadraticResidue(x, p)) x = Util.Mod(BigInteger.Negate(x), p);
        for (var i = 0; i < t; i++) y = Square(y, p);

        return x.CompareTo(y) == 0;
    }

    /// <summary>
    /// Calculates the modular exponentiation of a value raised to a specified exponent modulo a given modulus.
    /// </summary>
    /// <param name="value">The base value.</param>
    /// <param name="exponent">The exponent to raise the value to.</param>
    /// <param name="modulus">The modulus to perform the operation.</param>
    /// <returns>The result of the modular exponentiation operation.</returns>
    private BigInteger ModExp(BigInteger value, BigInteger exponent, BigInteger modulus)
    {
        return BigInteger.ModPow(value, exponent, modulus);
    }

    /// <summary>
    /// Checks if a given number is a quadratic residue modulo p.
    /// </summary>
    /// <param name="x">The number to be checked.</param>
    /// <param name="p">The modulo value.</param>
    /// <returns>True if x is a quadratic residue modulo p, false otherwise.</returns>
    private bool IsQuadraticResidue(BigInteger x, BigInteger p)
    {
        var t = ModExp(x, Div(Sub(p, new BigInteger(1)), new BigInteger(2)), p);
        return t.CompareTo(new BigInteger(1)) == 0;
    }


    /// <summary>
    /// Adds two BigInteger numbers.
    /// </summary>
    /// <param name="x">The first number to add.</param>
    /// <param name="y">The second number to add.</param>
    /// <returns>The sum of the two numbers <paramref name="x"/> and <paramref name="y"/>.</returns>
    private static BigInteger Add(BigInteger x, BigInteger y)
    {
        return BigInteger.Add(x, y);
    }

    /// <summary>
    /// Subtracts two BigIntegers.
    /// </summary>
    /// <param name="x">The first BigInteger.</param>
    /// <param name="y">The second BigInteger.</param>
    /// <returns>The result of subtracting y from x.</returns>
    private static BigInteger Sub(BigInteger x, BigInteger y)
    {
        return BigInteger.Subtract(x, y);
    }

    /// <summary>
    /// Divides two BigIntegers.
    /// </summary>
    /// <param name="x">The numerator.</param>
    /// <param name="y">The denominator.</param>
    /// <returns>The result of dividing x by y.</returns>
    private static BigInteger Div(BigInteger x, BigInteger y)
    {
        return BigInteger.Divide(x, y);
    }

    /// <summary>
    /// Calculates the modular square root of a number.
    /// </summary>
    /// <param name="x">The number for which to find the modular square root.</param>
    /// <param name="p">The modulus.</param>
    /// <returns>The modular square root of the number.</returns>
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
    /// Calculates the square of a given number modulus a given number.
    /// </summary>
    /// <param name="y">The number to calculate the square of.</param>
    /// <param name="p">The modulus value.</param>
    /// <returns>The square of the given number modulo the given number.</returns>
    private BigInteger Square(BigInteger y, BigInteger p)
    {
        return ModExp(y, new BigInteger(2), p);
    }

    /// <summary>
    /// Calculates the modular square root of a given number.
    /// </summary>
    /// <param name="t">The number of iterations to perform.</param>
    /// <param name="x">The number for which to calculate the modular square root.</param>
    /// <param name="p">The modulus.</param>
    /// <returns>The modular square root of the given number.</returns>
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
    /// Gets the prime bit value for a given PrimeBit enumeration.
    /// </summary>
    /// <param name="primeBit">The PrimeBit enumeration value.</param>
    /// <returns>The prime bit value as a string.</returns>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when the prime bit value is not supported.</exception>
    private static string GetPrimeBit(PrimeBit primeBit)
    {
        return primeBit switch
        {
            PrimeBit.P256 => PrimeBit256,
            PrimeBit.P512 => PrimeBit512,
            PrimeBit.P1024 => PrimeBit1024,
            _ => throw new ArgumentOutOfRangeException(nameof(primeBit), primeBit, "Prime bit not supported")
        };
    }
}