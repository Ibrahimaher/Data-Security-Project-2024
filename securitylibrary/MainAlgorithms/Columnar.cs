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
            //throw new NotImplementedException();
            /*cipherText = cipherText.ToLower();
            int Numberofrow = 0;
            int Numberofcol = 0;
            char[,] plain = new char[Numberofrow, Numberofcol];
            char[,] cipher = new char[Numberofrow, Numberofcol];*/
            int Numberofrow = 0;
            int Numberofcol = 0;
            cipherText = cipherText.ToLower();
           
            int i = 2;
            while ( i < 8)
            {
                if (cipherText.Length % i == 0)
                {
                    Numberofcol = i;
                }
                i++;
            }

            Numberofrow = cipherText.Length / Numberofcol;
            List<int> key = new List<int>(Numberofcol);

           
            int counter = 0;
            char[,] plaintext1 = new char[Numberofrow, Numberofcol];
            char[,] ciphertext1 = new char[Numberofrow, Numberofcol];
            int m = 0;
            while ( m < Numberofrow)
            {
                for (int j = 0; j < Numberofcol; j++)
                {
                    if (counter < plainText.Length)
                    {
                        plaintext1[m, j] = plainText[counter];
                        counter++;
                    }

                }
                m++;
            }
            int r = 0;
            counter = 0;
            while ( r < Numberofcol)
            {
                for (int j = 0; j < Numberofrow; j++)
                {
                    if (counter < cipherText.Length)
                    {
                        ciphertext1[j, r] = cipherText[counter];
                        counter++;
                    }
                }
                r++;
            }
          
            int shahd = 0;
            int h = 0;
            while ( h < Numberofcol)
            {
                for (int k = 0; k < Numberofcol; k++)
                {
                    for (int j = 0; j < Numberofrow; j++)
                    {
                        if (plaintext1[j, h] == ciphertext1[j, k])
                        {
                            shahd++;
                        }
                        if (shahd == Numberofrow)
                        {
                            key.Add(k + 1);
                        }
                    }
                    shahd = 0;
                }
                h++;
            }

            
            if (key.Count == 0)
            {
                for (int y = 0; y < Numberofcol + 2; y++)
                {
                    key.Add(0);
                }
            }
            return key;



        }

        public string Decrypt(string cipherText, List<int> key)
        {
            // throw new NotImplementedException();
            int Ncol = key.Count;
            
            int Nrow = cipherText.Length % Ncol == 0 ? cipherText.Length / Ncol : cipherText.Length / Ncol + 1; 
            char[,] mrx = new char[Nrow, Ncol];           
            int calc = 0;      
            int j = 0;
            
            while ( j < Ncol)
            {
               
                int colIndex = key.IndexOf(j + 1);
                
                for (int z = 0;  z < Nrow; z++)
                {
                    if (calc < cipherText.Length)
                    {
                          mrx[z, colIndex] = cipherText[calc];
                        calc++;
                    }
                  else
                    {
                        mrx[z, colIndex] = ' ';
                    }
                    
                }
                j++;
            }
            // show the final output 
            StringBuilder plaintextBuilder = new StringBuilder();
            int y = 0;
            while ( y < Nrow)
            {
                for (int k = 0; k < Ncol; k++)
                {
                    plaintextBuilder.Append(mrx[y, k]);
                }
                y++;
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
            int numofRows = plainText.Length / numofColumns + (plainText.Length % numofColumns == 0 ? 0 : 1);

            plainText = plainText.PadRight(numofRows * numofColumns, '\0');
            char[,] mtx = new char[numofRows, numofColumns];
            int calc = 0;  
           
            List<char> charList = new List<char>();
            int i = 0;
            while ( i < numofRows)
            {
                for (int j = 0; j < numofColumns; j++)
                {
                    mtx[i, key[j] - 1] = plainText[calc];

                    calc++;
                    charList.Add(mtx[i, j]);

                }
                i++;
            }
            string c = "";
            int column = 0;
           
            while ( column < numofColumns )
            {
                for (int row = 0; row < numofRows; row++)
                {
                    c += mtx[row, column];
                    
                }
                column++;
            }
            return c;


        }
    }
}
