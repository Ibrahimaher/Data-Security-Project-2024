using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        // Encrypts a message M using the public key (p, q) and exponent e
        public int Encrypt(int p, int q, int M, int e)
        {
            // Calculate the modulus n
            int n = p * q;

            // Encrypt the message using modular exponentiation
            int encryptedMessage = Mod_Power_Function(M, e, n);

            return encryptedMessage;
        }

        // Decrypts a ciphertext C using the private key (p, q) and exponent e
        public int Decrypt(int p, int q, int C, int e)
        {
            // Calculate the modulus n
            int n = p * q;

            // Calculate Euler's totient function (φ)
            int phi = (p - 1) * (q - 1);

            // Calculate the decryption exponent d
            int d = Appear_D_Function(e, phi);

            // Decrypt the ciphertext using modular exponentiation
            int decryptedMessage = Mod_Power_Function(C, d, n);

            return decryptedMessage;
        }

        // Performs modular exponentiation efficiently
        public int Mod_Power_Function(int baseValue, int exponent, int modulus)
        {
            int result = 1;

            // Iterate through each bit of the exponent
            while (exponent > 0)
            {
                // If the current bit is 1, multiply result with baseValue
                if ((exponent & 1) == 1)
                {
                    result = (int)(((long)result * baseValue) % modulus);
                }

                // Square baseValue and reduce modulo
                baseValue = (int)(((long)baseValue * baseValue) % modulus);

                // Move to the next bit by right-shifting the exponent
                exponent >>= 1;
            }

            return result;
        }

        // Finds the modular multiplicative inverse of q modulo p
        public int Appear_D_Function(int q, int p)
        {
            int h = 1;
            // Continuously search for h such that (q * h) % p == 1
            while (true)
            {
                if ((q * h) % p == 1)
                {
                    return h;
                }
                h++;
            }
        }
    }

}
