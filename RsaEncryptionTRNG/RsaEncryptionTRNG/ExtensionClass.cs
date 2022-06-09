using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

namespace RsaEncryptionTRNG
{
    internal static class ExtensionClass
    {
        static public bool isPrime(this int number)
        {
            if (number <= 1)
                return false;
            for (int i = 2; i <= number / 2; i++)
            {
                if (number % i == 0)
                { return false; }
            }
            return true;
        }

        static public bool isPrime(this BigInteger number)
        {
            if (number <= 1)
                return false;
            for (int i = 2; i <= number / 2; i++)
            {
                if (number % i == 0)
                { return false; }
            }
            return true;
        }

        static public bool BigIntegerPrimalityTest(this BigInteger number, int testLoop)
        {
            if (number < 3 || number.IsEven) return false;



            return false;
        }

        private static ThreadLocal<Random> s_Gen = new ThreadLocal<Random>(
      () => {
          return new Random();
      }
    );

        // Random generator (thread safe)
        private static Random Gen
        {
            get
            {
                return s_Gen.Value;
            }
        }

        public static bool IsProbablyPrime(this BigInteger value, int witnesses = 10)
        {
            if (value <= 1)
                return false;

            if (witnesses <= 0)
                witnesses = 10;

            BigInteger d = value - 1;
            int s = 0;

            while (d % 2 == 0)
            {
                d /= 2;
                s += 1;
            }

            Byte[] bytes = new Byte[value.ToByteArray().LongLength];
            BigInteger a;

            for (int i = 0; i < witnesses; i++)
            {
                do
                {
                    Gen.NextBytes(bytes);

                    a = new BigInteger(bytes);
                }
                while (a < 2 || a >= value - 2);

                BigInteger x = BigInteger.ModPow(a, d, value);
                if (x == 1 || x == value - 1)
                    continue;

                for (int r = 1; r < s; r++)
                {
                    x = BigInteger.ModPow(x, 2, value);

                    if (x == 1)
                        return false;
                    if (x == value - 1)
                        break;
                }

                if (x != value - 1)
                    return false;
            }

            return true;
        }


        // Function to find gcd
        // of two numbers
        public static BigInteger euclid(BigInteger m, BigInteger n)
        {
            if (n == 0)
            {
                return m;
            }
            else
            {
                BigInteger r = m % n;
                return euclid(n, r);
            }
        }

        // Program to find
        // Multiplicative inverse
        public static (BigInteger, BigInteger) exteuclid(BigInteger a, BigInteger b)
        {
            var r1 = a;
            var r2 = b;
            BigInteger s1 = 1;
            BigInteger s2 = 0;
            BigInteger t1 = 0;
            BigInteger t2 = 1;
            while (r2 > 0)
            {
                var q = r1 / r2;
                var r = r1 - q * r2;
                r1 = r2;
                r2 = r;
                var s = s1 - q * s2;
                s1 = s2;
                s2 = s;
                var t = t1 - q * t2;
                t1 = t2;
                t2 = t;
            }
            if (t1 < 0)
            {
                t1 = t1 % a;
            }
            return (r1, t1);
        }

        static public byte[] BigIntegerToRSAByteArray(this BigInteger parameter)
        {
            var temp = parameter.ToByteArray();

            if (temp.Length > 0 && temp[temp.Length - 1] == 0)
                Array.Resize(ref temp, temp.Length - 1);

            Array.Reverse(temp);
            return temp;
        }




    }
}
