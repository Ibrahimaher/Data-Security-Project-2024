using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        public string alphabet = "abcdefghijklmnopqrstuvwxyz";


        public int Letterind(char letter)
        {
            for (int i = 0; i < 26; i++)
            {
                if (letter == alphabet[i])
                {
                    return i;
                }
            }
            return 0;
        }
        public string Analyse(string plainText, string cipherText)
        {


            char[,] tab = new char[26, 26];
            string alpha = "abcdefghijklmnopqrstuvwxyz";
            int[] row = new int[26];
            int[] row1 = new int[25];
            int[] col = new int[26];
            int[] col1 = new int[25];
            for (int i = 0; i < 26; i++)
            {
                row[i] = i;
            }
            int q = 1;
            for (int i = 0; i < 25; i++)
            {
                row1[i] = q;
                q++;
            }
            int q1 = 25;
            for (int i = 0; i < 25; i++)
            {


                col1[i] = q1;
                q1--;



            }




            for (int i = 0; i < 26; i++)
            {
                char wow = alpha[i];

                int o1 = 0;
                for (int i1 = i; i1 >= 0; i1--)
                {
                    col[o1] = i1;
                    o1++;

                }
                for (int y = 0; y < i + 1; y++)
                {


                    tab[row[y], col[y]] = wow;
                }




            }



            for (int i = 0; i < 25; i++)
            {
                char wow = alpha[i];
                int r1 = i + 1;
                for (int u = 0; u < (25 - i); u++)
                {
                    tab[row[r1], col[u]] = wow;
                    r1++;
                }





            }





            StringBuilder sp = new StringBuilder(plainText);
            StringBuilder sc = new StringBuilder(cipherText.ToLower());

            int[] rowp = new int[sp.Length];
            for (int i = 0; i < sp.Length; i++)
            {
                for (int j = 0; j < alpha.Length; j++)
                {
                    if (alpha[j].Equals(sp[i]))
                    {
                        rowp[i] = j;
                    }
                }



            }
            StringBuilder w = new StringBuilder();
            for (int i = 0; i < sp.Length; i++)
            {
                for (int j = 0; j < alpha.Length; j++)
                {
                    if (sc[i].Equals(tab[rowp[i], j]))
                    {
                        w.Append(alpha[j]);
                    }
                }




            }
            StringBuilder yw = new StringBuilder();

            if (w[0].Equals('h'))
            {
                for (int i = 0; i < 8; i++)
                {
                    yw.Append(w[i]);
                }



            }
            else
            {
                for (int i = 0; i < 9; i++)
                {
                    yw.Append(w[i]);
                }



            }
            return yw.ToString();
        }

        public string Decrypt(string cipherText, string key)
        {
            // Convert the cipherText to lowercase to ensure uniformity
            cipherText = cipherText.ToLower();
            // Initialize the plaintext string
            string plain = null;
            // Loop through each character in the cipherText
            for (int x = 0; x < cipherText.Length; x++)
            {
                // Get the index of the current character in the alphabet
                int ci = Letterind(cipherText[x]);
                // Get the index of the corresponding character in the key
                int ki = Letterind(key[x]);
                // Calculate the decrypted character index
                int t = (ci - ki) % 26;
                // Handle negative indices by wrapping around to the end of the alphabet
                if (t < 0)
                {
                    t = (t + 26) % 26;
                }
                else
                {
                    t = t;
                }
                // Append the decrypted character to the plain text
                plain += alphabet[t];
                // Update the key by appending the decrypted character
                key += alphabet[t];
            }
            // Convert the plaintext to lowercase before returning
            return plain.ToLower();
        }

        public string Encrypt(string plainText, string key)
        {
            // Initialize the cipher text string
            string cipher = null;
            // Initialize the counter for appending characters from the plaintext to the key
            int s = 0;
            // Ensure that the key is of the same length as the plaintext
            for (int i = 0; i < plainText.Length; i++)
            {
                if (key.Length != plainText.Length)
                {
                    // If the key is shorter than the plaintext, append characters from the plaintext to the key
                    key = key + plainText[s];
                    s++;
                }
            }
            // Loop through each character in the plaintext
            for (int i = 0; i < plainText.Length; i++)
            {
                // Get the index of the current character in the alphabet
                int plainIdx = Letterind(plainText[i]);
                // Get the index of the corresponding character in the key
                int keyIdx = Letterind(key[i]);
                // Calculate the encrypted character index
                int encryptedIdx = (plainIdx + keyIdx) % 26;
                // Append the encrypted character to the cipher text
                cipher += alphabet[encryptedIdx];
            }
            // Convert the cipher text to uppercase before returning
            return cipher.ToUpper();
        }

    }
}