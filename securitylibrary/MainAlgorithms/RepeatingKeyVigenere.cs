using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        public char[,] createTable()
        {
            char[,] Table = new char[26, 26];

            for (int row = 0; row < 26; row++)
            {
                for (int col = 0; col < 26; col++)
                {
                    Table[row, col] = (char)('a' + (row + col) % 26);
                }
            }

            return Table;
        }




        public string Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.Trim().ToLower();
            plainText = plainText.Trim().ToLower();
            string AlphaPit = "abcdefghijklmnopqrstuvwxyz";
            char[,] table = createTable();
            string keyy = "";

            for (int i = 0; i < plainText.Length; i++)
            {
                char[] column = new char[table.GetLength(0)];
                for (int x = 0; x < table.GetLength(0); x++)
                {
                    int rowIndex = AlphaPit.IndexOf(plainText[i]);
                    column[x] = table[rowIndex, x];
                }

                int cIndex = -1;
                for (int j = 0; j < column.Length; j++)
                {
                    if (column[j] == cipherText[i])
                    {
                        cIndex = j;
                        break;
                    }
                }

                if (cIndex != -1)
                {
                    keyy += AlphaPit[cIndex];
                }


            }

            string normal = keyy.Substring(0, keyy.Length - 1);

            while (normal != "")
            {
                if (cipherText == Encrypt(plainText, normal))
                {
                    keyy = normal;
                }
                normal = normal.Substring(0, normal.Length - 1);
            }

            return keyy;
        }

        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.Trim().ToLower();
            key = key.ToLower().Trim();
            string AlphaPitic = "abcdefghijklmnopqrstuvwxyz";
            char[,] table = createTable();

            while (key.Length < cipherText.Length)
            {
                if (cipherText.Length - key.Length > key.Length)
                {
                    key = key + key;
                }
                else
                {
                    key = key + key.Substring(0, cipherText.Length - key.Length);
                }
            }

            string plainText = "";

            for (int c = 0; c < key.Length; c++)
            {
                char[] row = new char[table.GetLength(1)];

                for (int x = 0; x < table.GetLength(1); x++)
                {
                    row[x] = table[AlphaPitic.IndexOf(key[c]), x];
                }

                int cIndex = Array.IndexOf(row, cipherText[c]);

                if (cIndex != -1)
                {
                    plainText += AlphaPitic[cIndex];
                }

            }

            return plainText;
        }

        public string Encrypt(string plainText, string key)
        {
            plainText = plainText.Trim().ToLower();
            key = key.ToLower().Trim();
            string AlphaPitic = "abcdefghijklmnopqrstuvwxyz";
            char[,] table = createTable();

            while (key.Length < plainText.Length)
            {
                if (plainText.Length - key.Length > key.Length)
                {
                    key = key + key;
                }
                else
                {
                    key = key + key.Substring(0, plainText.Length - key.Length);
                }
            }

            string cipher = "";

            for (int i = 0; i < key.Length; i++)
            {
                cipher += table[AlphaPitic.IndexOf(key[i]), AlphaPitic.IndexOf(plainText[i])];
            }

            return cipher;
        }


    }
}