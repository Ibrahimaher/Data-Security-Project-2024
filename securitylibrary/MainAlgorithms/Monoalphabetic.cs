using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        int index;
        bool check_contain(char[] x, char y)
        {

            return !x.Contains(y);
        }
        string alph = "abcdefghijklmnopqrstuvwxyz";

        public string Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToLower();

            string skeys = "";


            cipherText = cipherText.ToLower();
            string remains = "";
            char[] all_chars = new char[26];



            for (int i = 0; i < plainText.Length; i++)
            {
                int index_n_alph = alph.IndexOf(plainText[i]);
                all_chars[index_n_alph] = cipherText[i];
            }
            for (int i = 0; i < 26; i++)
            {
                if (check_contain(all_chars, alph[i]))
                    remains += alph[i];
            }

            int l = 0;
            int z = 0;
            while (z < 26)
            {
                if (!alph.Contains(all_chars[z]))
                {
                    all_chars[z] = remains[l];
                    l++;
                }
                z++;
            }

            int k = 0;

            for (k = 0; k < all_chars.Length; k++)
            {

                skeys += all_chars[k];
            }

            return skeys.ToLower();



            //throw new NotImplementedException();
        }


        public string Decrypt(string cipherText, string key)
        {

            string plainText = "";
            cipherText = cipherText.ToLower();

            key = key.ToLower();
            for (int i = 0; i < cipherText.Length; i++)
            {
                int kayId;

                int j = 0;
                while (j < key.Length)
                {
                    if (key[j] == cipherText[i])
                    {
                        index = j;
                    }


                    j++;
                }
                kayId = index;
                plainText += alph[kayId];


            }
            return plainText.ToLower();

        }

        public string Encrypt(string plainText, string key)
        {


            string encryptedText = "";

            for (int i = 0; i < plainText.Length; i++)
            {
                char l = plainText[i];

                int kayInd;

                int j = 0;
                while (j < alph.Length)
                {
                    if (alph[j] == l)
                    {
                        index = j;
                    }
                    j++;
                }

                kayInd = index;

                encryptedText += key[kayInd];

            }

            return encryptedText.ToUpper();
            //  throw new NotImplementedException();


        }




        public string AnalyseUsingCharFrequency(string cipher)
        {
            Dictionary<char, char> keysdic = new Dictionary<char, char>();

            string alphabitFrequencys = "ETAOINSRHLDCUMFPGWYBVKXJQZ".ToLower();

            StringBuilder result = new StringBuilder("");
            cipher = cipher.ToLower();
            Dictionary<char, int> inputFreq = new Dictionary<char, int>();



            foreach (char c in cipher)
            {
                if (!inputFreq.ContainsKey(c))
                {


                    inputFreq.Add(c, 1);
                }
                else
                {

                    inputFreq[c]++;
                }
            }




            IEnumerable<KeyValuePair<char, int>> sortedInputFrequency = inputFreq.OrderByDescending(entry => entry.Value);

            for (int i = 0; i < sortedInputFrequency.Count(); i++)
            {
                var entry = sortedInputFrequency.ElementAt(i);
                keysdic[entry.Key] = alphabitFrequencys[i];
            }

            foreach (char c in cipher)
            {

                if (keysdic.ContainsKey(c))
                {

                    result.Append(keysdic[c]);
                }
                else
                {

                    result.Append(c);
                }
            }

            return result.ToString();
        }
    }
}