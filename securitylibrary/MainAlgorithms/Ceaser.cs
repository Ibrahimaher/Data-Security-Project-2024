using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {

        string resultofcipher;
        public string Encrypt(string plainText, int key)
        {
            // throw new NotImplementedException();
            Console.WriteLine(plainText);
            string y = "abcdefghijklmnopqrstuvwxyz";
            int i = 0;
            while(i<plainText.Length)
            {
                int idx = y.IndexOf(plainText[i]);
                // Console.WriteLine(idx);
                resultofcipher += y[((idx + key) % 26)];
                Console.WriteLine(resultofcipher);
                i++;
            }
            return resultofcipher.ToUpper();
        }
        string resultofplaintext;
        public string Decrypt(string cipherText, int key)
        {
            // throw new NotImplementedException();
            Console.WriteLine(cipherText);
            string y = "abcdefghijklmnopqrstuvwxyz".ToUpper();
            int j = 0;
            while ( j < cipherText.Length)
            {
                int idx = y.IndexOf(cipherText[j]);
                int z = (idx - key);
                if (z < 0)
                    z += 26;
                resultofplaintext += y[(z % 26)];
                j++;
            }

            return resultofplaintext.ToLower();
        }
        int key;
        public int Analyse(string plainText, string cipherText)
        {
            // throw new NotImplementedException();
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            //throw new NotImplementedException();
            string y = "abcdefghijklmnopqrstuvwxyz";
            int k = 0;
            while ( k < plainText.Length)
            {

                int idx1 = y.IndexOf(cipherText[k]);
                int idx2 = y.IndexOf(plainText[k]);
                key = (idx1 - idx2) % 26;
                if (key < 0)
                    key += 26;

                k++;
            }
            return key;
        }
    }
}
