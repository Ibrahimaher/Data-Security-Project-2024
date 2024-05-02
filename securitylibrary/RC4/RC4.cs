using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RC4
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class RC4 : CryptographicTechnique
    {
        private byte[] S = new byte[256];
        private byte[] key;
        int number = 256;

        void swap(int[] s, int[] q)
        {
            int j = 0;

            int index = 0;

            while (index < number)
            {
                j = (j + s[index] + q[index]) % number;

                int tmp = s[index];
                s[index] = s[j];
                s[j] = tmp;
                index++;
            }

        }

        public override string Decrypt(string cipherText, string key)
        {
            return Encrypt(cipherText, key);

            // throw new NotImplementedException();
        }

        public override string Encrypt(string plainText, string key)
        {
            if (key[0] == '0' && key[1] == 'x')
            {
                string tmpK = "";
                int o = 2;
                while (o < key.Length)
                {
                    tmpK += char.ConvertFromUtf32(Convert.ToInt32(key[o].ToString() + key[o + 1].ToString(), 16));
                    o += 2;
                }




                key = tmpK;
            }
            bool f = false;
            if (plainText[1] == 'x' && plainText[0] == '0')
            {
                f = true;
                string tmpP = "";
                for (int i = 2; i < plainText.Length; i += 2)
                {
                    tmpP += char.ConvertFromUtf32(Convert.ToInt32(plainText[i].ToString() + plainText[i + 1].ToString(), 16));
                }
                plainText = tmpP;
            }


            int[] S = new int[number];
            int[] T = new int[number];
            int m = 0;
            while (m < number)
            {
                S[m] = m;
                T[m] = key[m % key.Length];
                m++;
            }


            swap(S, T);


            int u = 0;

            int p = 0;

            int v = 0;

            int t;

            string C = "";
            for (int i = 0; i < plainText.Length; i++)
            {
                u = (u + 1) % number;


                p = (p + S[u]) % number;
                int tmp;


                tmp = S[u];
                S[u] = S[p];

                S[p] = tmp;
                t = (S[u] + S[p]) % number;
                v = S[t];
                C += char.ConvertFromUtf32((plainText[i] ^ v));
            }

            if (f == true)
            {
                C = string.Join("", C.Select(c => ((int)c).ToString("x2")));


                C = "0x" + C;
            }
            return C;
            // throw new NotImplementedException();        }
        }
    }
}
