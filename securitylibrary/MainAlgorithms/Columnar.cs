using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            // throw new NotImplementedException();

            // calculate the number of columns based on the length of the key
            int numofCols = key.Count;
            // calculate the number of rows based on the length of the ciphertext and the number of columns
            int numofRows = (int)Math.Ceiling((double)cipherText.Length / numofCols);
            // initialize the matrix to store the ciphertext
            char[,] mrx = new char[numofRows, numofCols];
            // initialize the index to keep track of the position in the ciphertext string
            int calc = 0;
            // fill the matrix column by column
            for (int j = 0; j < numofCols; j++)
            {
                // get the index of the current column in the key
                int colIndex = key.IndexOf(j + 1);
                // fill the column from top to bottom
                for (int i = 0; i < numofRows; i++)
                {
                    if (calc < cipherText.Length)
                    {
                        mrx[i, colIndex] = cipherText[calc];
                        calc++;
                    }
                    else
                    {
                        mrx[i, colIndex] = ' ';
                    }
                }
            }
            // read the matrix row by row to get the plaintext
            StringBuilder plaintextBuilder = new StringBuilder();
            for (int i = 0; i < numofRows; i++)
            {
                for (int j = 0; j < numofCols; j++)
                {
                    plaintextBuilder.Append(mrx[i, j]);
                }
            }
            // remove any trailing spaces
            string plaintext = plaintextBuilder.ToString().Trim();
            return plaintext;
        }

        public string Encrypt(string plainText, List<int> key)
        {
            // throw new NotImplementedException();
            plainText = plainText.Replace(" ", "").Replace(".", "");
            int numofColumns = key.Count;
            int numofRows = (int)Math.Ceiling((double)plainText.Length / numofColumns);
            plainText = plainText.PadRight(numofRows * numofColumns, '\0');
            char[,] mtx = new char[numofRows, numofColumns];
            int calc = 0;

            for (int row = 0; row < numofRows; row++)
            {
                for (int col = 0; col < key.Count && calc < plainText.Length; col++)
                { 
                    mtx[row, col] = plainText[calc];
                    calc++;
                  
                }
            }
            string c = "";

            for (int col = 0; col < numofColumns; col++)
            {
                for (int row = 0; row < numofRows; row++)
                {
                    c += mtx[row, col];
                }
            }
            return c;


        }
    }
}
