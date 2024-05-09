using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace SecurityLibrary.ElGamal
{
    public class ElGamal
    {
        public long Modpower(long baseNumber, long pow, long modulus)
        {
            long outputt = 1;
            baseNumber %= modulus;

            for (long i = 0; i < pow; i++)
            {
                outputt = (outputt * baseNumber) % modulus;
            }

            return outputt;
        }
        public int ModInverse(int a, int mod)
        {
            int m = mod;
            int y = 0;
            int x = 1;

            while (a > 1)
            {
                int q = a / mod;
                int t = mod;
                mod = a % mod;
                a = t;
                t = y;

                y = x - q * y;
                x = t;
            }

            if (x < 0)
                x += m;

            return x;
        }

        public List<long> Encrypt(int q, int alpha, int y, int k, int m)
        {
            long c1 = Modpower(alpha, k, q);
            long c2 = (Modpower(y, k, q) * m) % q;

            return new List<long> { c1, c2 };
        }

        public int Decrypt(int c1, int c2, int x, int q)
        {
            int c1_inverse = ModInverse(c1, q);
            int c1_power = (int)Modpower(c1_inverse, x, q);
            int m = (c2 * c1_power) % q;

            return m;
        }


    }
}