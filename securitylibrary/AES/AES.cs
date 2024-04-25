using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {
        //encryption
        // Constants and matrices for encryption
        int[,] matrix = new int[4, 4]; // State matrix
        int[,] MixColumn_matrix = new int[4, 4]; // MixColumns matrix
        int[,] curKey = new int[4, 4]; // Current encryption key

        int[,] s_box = {   // S-box values in hexadecimal
     { 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76 },
     { 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0 },
     { 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15 },
     { 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75 },
     { 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
     { 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
     { 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8 },
     { 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2 },
     {  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73 },
     { 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb },
     { 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79 },
     { 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08 },
     { 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a },
     { 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e },
     { 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf },
     { 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 },
 };
        int[,] I_s_box = new int[16, 16];
        //encryption
        public void Creatematrix(string plain, int method)
        {
            // Extract values from input string and fill the appropriate matrix
            int ind = 0;
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    string prefixHex = "0x" + plain[ind] + plain[ind + 1];
                    int intValue = Convert.ToInt32(prefixHex, 16);
                    ind += 2;
                    if (method == 1)
                        matrix[j, i] = intValue;
                    else if (method == 2)
                        MixColumn_matrix[i, j] = intValue;
                    else if (method == 3)
                        curKey[j, i] = intValue;
                }
            }
        }
        public bool checkfirstbit(int num)
        {
            return (num >> 7 & 1) == 1;
        }
        public int mantainsize(int number)
        {
            number = number << 1;
            return (number % 256);
        }
        public int fastpower(int n, int p)
        {
            if (p == 1)
                return n;
            int temp = 0;
            if (p % 2 == 1)
            {
                temp ^= n;
            }

            int temp2 = fastpower(n, p / 2);
            if (checkfirstbit(temp2) == true)
            {
                temp2 = mantainsize(temp2);
                temp2 ^= 27;
            }
            //0
            else
            {
                temp2 = mantainsize(temp2);
            }
            return temp2 ^ temp;
        }
        public void MixColumns()
        {
            // Perform MixColumns operation on the state matrix
            for (int column = 0; column < 4; column++)
            {
                int[,] tempx = new int[4, 1];
                //creating
                for (int i = 0; i < 4; i++)
                {
                    for (int j = 0; j < 4; j++)
                    {
                        tempx[i, 0] ^= fastpower(matrix[j, column], MixColumn_matrix[i, j]);
                    }
                }

                for (int i = 0; i < 4; ++i)
                {
                    matrix[i, column] = tempx[i, 0];
                }
            }
        }
        public void RoundKey()
        {
            // Add round key to the state matrix
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    matrix[i, j] = curKey[i, j] ^ matrix[i, j];
                }
            }
        }
        public void Shift_rows(int size)
        {
            // Perform ShiftRows operation on the state matrix
            /*1 2  3 4
             *5 6  7 8 
             *9 10 11 12
             *13 14 15 16 
             * 
             * 
             */

            int temp2 = 0;
            for (int i = 1; i < size; i++)
            {
                for (int k = 0; k < i; k++)
                {
                    temp2 = matrix[i, 0];
                    for (int j = 0; j < size; j++)
                    {
                        if (j < 3)
                        {
                            matrix[i, j] = matrix[i, j + 1];
                        }
                        else
                        {
                            matrix[i, j] = temp2;
                        }
                    }
                }
            }
        }
        public void Sub_bytes(ref int[,] matrix, int rows, int column)
        {
            // Perform SubBytes operation on the state matrix using the S-box
            int temp = 0;
            for (int i = 0; i < rows; i++)
            {
                for (int j = 0; j < column; j++)
                {
                    temp = matrix[i, j];
                    matrix[i, j] = s_box[temp / 16, temp % 16];
                }
            }
        }
        public void keySchedule(int round)
        {
            // Generate round keys based on the current encryption key and round number
            string Rcon = "01020408102040801b36";
            int[,] Rconmatrix = new int[4, 1];
            int intValue = Convert.ToInt32(Rcon.Substring(round * 2, 2), 16);
            Rconmatrix[0, 0] = intValue;
            int[,] temp = new int[4, 1];
            temp[3, 0] = curKey[0, 3];
            for (int i = 0; i < 3; i++)
                temp[i, 0] = curKey[i + 1, 3];
            Sub_bytes(ref temp, 4, 1);
            for (int i = 0; i < 4; i++)
            {
                curKey[i, 0] = curKey[i, 0] ^ temp[i, 0] ^ Rconmatrix[i, 0];
            }
            for (int i = 0; i < 4; i++)
            {
                for (int j = 1; j < 4; j++)
                {
                    curKey[i, j] = curKey[i, j - 1] ^ curKey[i, j];
                }
            }
        }
        public string GetFinalstring()
        {
            // Convert state matrix to string
            string temp = "";
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    string temp2 = matrix[j, i].ToString("x");
                    if (temp2.Length < 2)
                        temp += "0" + temp2;
                    else
                        temp += temp2;
                }

            }
            temp = temp.ToUpper();
            temp = "0x" + temp;
            return temp;
        }

        //decryption
        public void inv_shiftrows()
        {
            // Perform inverse ShiftRows operation on the state matrix
            for (int i = 1; i < 4; i++)
            {
                for (int k = 0; k < i; k++)
                {
                    int temp = matrix[i, 3];
                    for (int j = 2; j >= 0; j--)
                    {
                        matrix[i, j + 1] = matrix[i, j];
                    }
                    matrix[i, 0] = temp;
                }
            }
        }

        // Decryption steps
        public void keyschedule_inv(int round)
        {
            // Generate inverse round keys based on the current encryption key and round number

            string Rcon = "01020408102040801b36";
            int[,] Rconmatrix = new int[4, 1];
            int intValue = Convert.ToInt32(Rcon.Substring(round * 2, 2), 16);
            Rconmatrix[0, 0] = intValue;
            int[,] temp = new int[4, 1];
            //column
            for (int i = 3; i >= 1; i--)
            {
                //row
                for (int j = 0; j < 4; j++)
                {
                    curKey[j, i] = curKey[j, i] ^ curKey[j, i - 1];
                }
            }
            temp[3, 0] = curKey[0, 3];
            for (int i = 0; i < 3; i++)
                temp[i, 0] = curKey[i + 1, 3];
            Sub_bytes(ref temp, 4, 1);
            for (int i = 0; i < 4; i++)
            {
                curKey[i, 0] = curKey[i, 0] ^ temp[i, 0] ^ Rconmatrix[i, 0];
            }

        }
        public void S_index_inv(int[,] matrix, int size)
        {
            // Perform inverse SubBytes operation on the state matrix using the inverse S-box
            for (int i = 0; i < size; i++)
            {
                for (int j = 0; j < size; j++)
                {
                    matrix[i, j] = I_s_box[matrix[i, j] / 16, matrix[i, j] % 16];
                }

            }
            for (int i = 0; i < size; i++)
            {
                for (int j = 0; j < size; j++)
                {
                    Console.WriteLine(matrix[i, j].ToString("x"));
                }

            }


        }
        public void S_index_inv_create()
        {
            // Create the inverse S-box
            //check for the element if found 
            int[,] s_box = {
     { 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76 },
     { 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0 },
     { 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15 },
     { 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75 },
     { 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
     { 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
     { 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8 },
     { 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2 },
     {  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73 },
     { 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb },
     { 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79 },
     { 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08 },
     { 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a },
     { 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e },
     { 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf },
     { 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 },
 };
            int temp = 0;
            int x = 0, y = 0;
            for (int i = 0; i < 16; i++)
            {

                for (int j = 0; j < 16; j++)
                {
                    temp = s_box[i, j];
                    I_s_box[temp / 16, temp % 16] = i * 16 + j;
                }
            }
        }

        public override string Decrypt(string cipherText, string key)
        {
            string inverse_Mcolumn = "0E0B0D09090E0B0D0D090E0B0B0D090E";
            cipherText = cipherText.Remove(0, 2);
            key = key.Remove(0, 2);
            cipherText = cipherText.ToLower();
            key = key.ToLower();
            Creatematrix(cipherText, 1);
            Creatematrix(inverse_Mcolumn, 2);
            Creatematrix(key, 3);
            S_index_inv_create();
            for (int i = 0; i < 10; i++)
                keySchedule(i);
            //round 0
            RoundKey();
            inv_shiftrows();
            S_index_inv(matrix, 4);

            for (int i = 9; i >= 1; i--)
            {
                keyschedule_inv(i);
                RoundKey();
                MixColumns();
                inv_shiftrows();
                S_index_inv(matrix, 4);
            }
            keyschedule_inv(0);
            RoundKey();
            string temp = GetFinalstring();
            return temp;

        }

        public override string Encrypt(string plainText, string key)
        {
            string Mcolumn_matrix = "02030101010203010101020303010102";
            plainText = plainText.Remove(0, 2);
            key = key.Remove(0, 2);
            plainText = plainText.ToLower();
            key = key.ToLower();
            Creatematrix(plainText, 1);
            Creatematrix(Mcolumn_matrix, 2);
            Creatematrix(key, 3);
            //round 0
            RoundKey();
            keySchedule(0);
            // round 1-9  
            for (int i = 1; i < 10; i++)
            {
                Sub_bytes(ref matrix, 4, 4);
                Shift_rows(4);
                MixColumns();
                RoundKey();
                keySchedule(i);
            }
            //last round
            Sub_bytes(ref matrix, 4, 4);
            Shift_rows(4);
            RoundKey();
            return GetFinalstring();

        }
    }
}