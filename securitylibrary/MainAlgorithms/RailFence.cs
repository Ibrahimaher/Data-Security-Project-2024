using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            plainText = plainText.ToLower();
            int PTlength = plainText.Length;
            int[] key = new int[PTlength];
            int keylength = key.Length;
            for (int i = 0; i < PTlength; i++)
            {
                if (plainText[i] == cipherText[1])
                {
                    key[i] = i;
                }
            }
            for (int j = 0; j < keylength; j++)
            {
                string strciphtxt = Encrypt(plainText, key[j]);
                strciphtxt = strciphtxt.ToLower();
                if (String.Equals(cipherText, strciphtxt))
                {
                    return key[j];
                }
            }
            return -1;
        }
        public string Decrypt(string cipherText, int key)
        {
            String plainText = "";
            cipherText = cipherText.ToLower();
            double CPlength = cipherText.Length;
            int pltlength = (int)Math.Ceiling(CPlength / key);
            char[] matrix = cipherText.ToCharArray();
            for (int i = 0; i < pltlength; i++)
            {
                for (int j = i; j < CPlength; j += pltlength)
                {
                    plainText += matrix[j];
                }
            }
            plainText = plainText.ToLower();
            return plainText;
        }
        public string Encrypt(string plainText, int key)
        {
            String cipherText = "";
            plainText = plainText.ToLower();
            int PLtlength = plainText.Length;
            char[] matrix = plainText.ToCharArray();

            for (int i = 0; i < key; i++)
            {
                for (int j = i; j < PLtlength; j += key)
                {
                    cipherText += matrix[j];
                }
            }
            return cipherText;
        }
    }
}