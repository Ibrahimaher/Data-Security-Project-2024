
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographicTechnique<string, string>
    {
        /// <summary>
        /// The most common diagrams in english (sorted): TH, HE, AN, IN, ER, ON, RE, ED, ND, HA, AT, EN, ES, OF, NT, EA, TI, TO, IO, LE, IS, OU, AR, AS, DE, RT, VE
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="cipherText"></param>
        /// <returns></returns>
        public string Analyse(string plainText)
        {
            throw new NotImplementedException();
        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }

        public string Decrypt(string cipherText, string key)
        {
            string ciphertxt = handle_plaintext_function(cipherText);
            string str = DecryptLogic(cipherText, key);

            return str;
        }

        public string Encrypt(string plainText, string key)
        {
            string plaintxt = handle_plaintext_function(plainText);
            string str = EncryptLogic(plaintxt, key);

            return str;
        }

        public string handle_plaintext_function(string palin_text)
        {
            string tmp_plaintxt = palin_text;

            //check if a pair have the same leter add x
            int k = 0;

            for (int i = 0; ((i < tmp_plaintxt.Length) && ((i + 1) < tmp_plaintxt.Length)); i += 2)
            {
                if (tmp_plaintxt[i] == tmp_plaintxt[i + 1])
                {
                    tmp_plaintxt = tmp_plaintxt.Insert(i + 1, "X");
                }

                k++;
            }



            //check if odd append x at the end
            if (tmp_plaintxt.Length % 2 != 0)
                tmp_plaintxt += 'X';

            tmp_plaintxt = tmp_plaintxt.ToUpper();

            return tmp_plaintxt;
        }

        public char[,] generateKeyMatrix(string key)
        {
            string defaultKeySquare = "ABCDEFGHIKLMNOPQRSTUVWXYZ";
            char[,] arr = new char[5, 5];
            key = key.ToUpper();

            // Replace each J letter with the letter I
            key = key.Replace('J', 'I');

            // Combine unique characters from key and defaultKeySquare
            string combinedKey = new String(key.Distinct().ToArray()) + defaultKeySquare;
            combinedKey = new String(combinedKey.Distinct().ToArray());

            // Take the first 25 characters to fill the matrix
            string keyMatrixString = combinedKey.Substring(0, 25);

            // Fill the matrix with characters from keyMatrixString
            int k = 0;
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    arr[i, j] = keyMatrixString[k];
                    k++;
                }
            }

            return arr;
        }


        public void GetIndexFunction(char[,] matrix, char ch, ref int row, ref int col)
        {
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    if (matrix[i, j] == ch)
                    {
                        row = i;
                        col = j;
                    }
                }
            }

        }

        public string EncryptLogic(string input, string key)
        {
            // Convert the input to uppercase and initialize a StringBuilder to store the encrypted result
            StringBuilder result = new StringBuilder(input.ToUpper());

            // Loop through the input string by pairs of characters
            for (int i = 0; i < input.Length; i += 2)
            {
                int row1 = 0, row2 = 0, col1 = 0, col2 = 0;

                // Generate the key matrix
                char[,] matrix = generateKeyMatrix(key);

                // Get the row and column indices of the first character in the pair
                GetIndexFunction(matrix, input[i], ref row1, ref col1);

                // Get the row and column indices of the second character in the pair
                GetIndexFunction(matrix, input[i + 1], ref row2, ref col2);

                // If both characters are in the same row
                if (row1 == row2)
                {
                    // Encrypt by shifting each character to the right (circular shift)
                    result[i] = matrix[row1, (col1 + 1) % 5];
                    result[i + 1] = matrix[row2, (col2 + 1) % 5];
                }
                // If both characters are in the same column
                else if (col1 == col2)
                {
                    // Encrypt by shifting each character down (circular shift)
                    result[i] = matrix[(row1 + 1) % 5, col1];
                    result[i + 1] = matrix[(row2 + 1) % 5, col2];
                }
                // If characters are neither in the same row nor in the same column (forming a rectangle)
                else
                {
                    // Encrypt by replacing characters based on the rectangle formed by the pair
                    result[i] = matrix[row1, col2];
                    result[i + 1] = matrix[row2, col1];
                }
            }

            // Convert the result to a string
            string strResult = result.ToString();

            // Return the encrypted result
            return strResult;
        }



        public string DecryptLogic(string input, string key)
        {
            // Convert the input to uppercase and initialize a StringBuilder to store the decrypted result
            StringBuilder result = new StringBuilder(input.ToUpper());

            // Generate key matrix
            char[,] matrix = generateKeyMatrix(key);

            // Loop through the input string by pairs of characters
            for (int i = 0; i < input.Length; i += 2)
            {
                int row1 = 0, row2 = 0, col1 = 0, col2 = 0;

                // Get the row and column indices of the first character in the pair
                GetIndexFunction(matrix, input[i], ref row1, ref col1);

                // Get the row and column indices of the second character in the pair
                GetIndexFunction(matrix, input[i + 1], ref row2, ref col2);

                // If both characters are in the same row
                if (row1 == row2)
                {
                    // Decrypt by shifting each character to the left (circular shift)
                    result[i] = matrix[row1, (col1 + 4) % 5];
                    result[i + 1] = matrix[row2, (col2 + 4) % 5];
                }
                // If both characters are in the same column
                else if (col1 == col2)
                {
                    // Decrypt by shifting each character up (circular shift)
                    result[i] = matrix[(row1 + 4) % 5, col1];
                    result[i + 1] = matrix[(row2 + 4) % 5, col2];
                }
                // If characters are neither in the same row nor in the same column (forming a rectangle)
                else
                {
                    // Decrypt by replacing characters based on the rectangle formed by the pair
                    result[i] = matrix[row1, col2];
                    result[i + 1] = matrix[row2, col1];
                }
            }

            // Convert the result to a string
            string str = result.ToString();
            string val = str.Substring(0, 1);

            // Remove padding 'X' characters
            for (int i = 1; i < str.Length - 1; i++)
            {
                if (!(str[i] == 'X' && str[i - 1] == str[i + 1] && i % 2 != 0))
                {
                    val += str.Substring(i, 1);
                }
            }

            // Add the last character if it's not 'X'
            if (str[str.Length - 1] != 'X')
                val += str.Substring(str.Length - 1, 1);

            // Convert the decrypted result to lowercase
            str = val.ToLower();

            // Return the decrypted result
            return str;
        }




    }
}