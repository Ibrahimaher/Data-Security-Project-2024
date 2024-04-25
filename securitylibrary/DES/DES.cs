using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class DES : CryptographicTechnique
    {
        //pre_functions
        public void ShiftLeft(List<string> a, List<string> b, string key2, string key1)
        {
            for (int i = 0; i < 16; i++)
            {
                string temp1 = key1.Substring(0, 1);
                key1 = key1.Remove(0, 1) + temp1;

                string temp2 = key2.Substring(0, 1);
                key2 = key2.Remove(0, 1) + temp2;

                if (i != 0 && i != 1)
                {
                    if (i != 8 && i != 15)
                    {
                        temp1 = key1.Substring(0, 1);

                        key1 = key1.Remove(0, 1) + temp1;
                        temp2 = key2.Substring(0, 1);
                        key2 = key2.Remove(0, 1) + temp2;
                    }
                }

                a.Add(key1);
                b.Add(key2);
            }
        }
        public string Permutaion(int[,] table, string In, int nRows, int nCol)
        {
            var output = new StringBuilder(nRows * nCol);
            for (int x = 0; x < nRows; x++)
            {
                for (int z = 0; z < nCol; z++)
                {
                    int index = table[x, z] - 1;
                    if (index < 0 || index >= In.Length)
                    {
                        throw new ArgumentException("Invalid index.");
                    }
                    output.Append(In[index]);
                }
            }
            return output.ToString();
        }

        public List<string> round(List<string> keys)
        {
            List<string> roundKeys = new List<string>();
            foreach (string key in keys)
            {
                string roundKey = Permutaion(P_C_2, key, 8, 6);
                roundKeys.Add(roundKey);
            }
            return roundKeys;
        }

        public string Sub_BOXES(List<string> separatedPlain)
        {
            StringBuilder res = new StringBuilder();

            for (int i = 0; i < separatedPlain.Count; i++)
            {
                string t = separatedPlain[i];
                string temp1 = $"{t[0]}{t[5]}";
                string temp2 = $"{t[1]}{t[2]}{t[3]}{t[4]}";

                int row = Convert.ToInt32(temp1, 2);
                int col = Convert.ToInt32(temp2, 2);

                int result = 0;

                if (i == 0)
                {
                    result = sub_Box1[row, col];
                }
                else if (i == 1)
                {
                    result = sub_Box2[row, col];
                }
                else if (i == 2)
                {
                    result = sub_Box3[row, col];
                }
                else if (i == 3)
                {
                    result = sub_Box4[row, col];
                }
                else if (i == 4)
                {
                    result = sub_Box5[row, col];
                }
                else if (i == 5)
                {
                    result = sub_Box6[row, col];
                }
                else if (i == 6)
                {
                    result = sub_Box7[row, col];
                }
                else if (i == 7)
                {
                    result = sub_Box8[row, col];
                }
                res.Append(Convert.ToString(result, 2).PadLeft(4, '0'));
            }

            return res.ToString();
        }

        //permuted_choice_and_sboxes 

        int[,] P_C_1 = new int[8, 7] {
                 { 57, 49, 41, 33, 25, 17, 9 },
                 { 1, 58, 50, 42, 34, 26, 18 },
                 { 10, 2, 59, 51, 43, 35, 27 },
                 { 19, 11, 3, 60, 52, 44, 36 },
                 { 63, 55, 47, 39, 31, 23, 15 },
                 { 7, 62, 54, 46, 38, 30, 22 },
                 { 14, 6, 61, 53, 45, 37, 29 },
                 { 21, 13, 5, 28, 20, 12, 4 } };

        int[,] P_C_2 = new int[8, 6] {
                 { 14, 17, 11, 24, 1, 5 },
                 { 3, 28, 15, 6, 21, 10 },
                 { 23, 19, 12, 4, 26, 8 },
                 { 16, 7, 27, 20, 13, 2 },
                 { 41, 52, 31, 37, 47, 55 },
                 { 30, 40, 51, 45, 33, 48 },
                 { 44, 49, 39, 56, 34, 53 },
                 { 46, 42, 50, 36, 29, 32 } };

        //1
        int[,] sub_Box1 = new int[4, 16] {
                 { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 },
                 { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 },
                 { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 },
                 { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 } };
        //2
        int[,] sub_Box2 = new int[4, 16] {
                 { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 },
                 { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 },
                 { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 },
                 { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 } };
        //3
        int[,] sub_Box3 = new int[4, 16] {
                 { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 },
                 { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 },
                 { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 },
                 { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 } };
        //4
        int[,] sub_Box4 = new int[4, 16] {
                 { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 },
                 { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 },
                 { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 },
                 { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 } };
        //5
        int[,] sub_Box5 = new int[4, 16] {
                 { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 },
                 { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 },
                 { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 },
                 { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 } };
        //6
        int[,] sub_Box6 = new int[4, 16] {
                 { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 },
                 { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 },
                 { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 },
                 { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 } };
        //7
        int[,] sub_Box7 = new int[4, 16] {
                 { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 },
                 { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 },
                 { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 },
                 { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 } };
        //8
        int[,] sub_Box8 = new int[4, 16] {
                 { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 },
                 { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 },
                 { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 },
                 { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } };

        int[,] Permute = new int[8, 4] {
                 { 16, 7, 20, 21 },
                 { 29, 12, 28, 17 },
                 { 1, 15, 23, 26 },
                 { 5, 18, 31, 10 },
                 { 2, 8, 24, 14 },
                 { 32, 27, 3, 9 },
                 { 19, 13, 30, 6 },
                 { 22, 11, 4, 25 } };

        int[,] Exp_Permutation = new int[8, 6] {
                 { 32, 1, 2, 3, 4, 5 },
                 { 4, 5, 6, 7, 8, 9  },
                 { 8, 9, 10, 11, 12, 13 },
                 { 12, 13, 14, 15, 16, 17 },
                 { 16, 17, 18, 19, 20, 21 },
                 { 20, 21, 22, 23, 24, 25 },
                 { 24, 25, 26, 27, 28, 29 },
                 { 28, 29, 30, 31, 32, 1  } };

        int[,] Init_Permutation = new int[8, 8] {
                 { 58, 50, 42, 34, 26, 18, 10, 2 },
                 { 60, 52, 44, 36, 28, 20, 12, 4 },
                 { 62, 54, 46, 38, 30, 22, 14, 6 },
                 { 64, 56, 48, 40, 32, 24, 16, 8 },
                 { 57, 49, 41, 33, 25, 17, 9, 1  },
                 { 59, 51, 43, 35, 27, 19, 11, 3 },
                 { 61, 53, 45, 37, 29, 21, 13, 5 },
                 { 63, 55, 47, 39, 31, 23, 15, 7 } };

        int[,] Init_Permutation_inverse = new int[8, 8] {
                 { 40, 8, 48, 16, 56, 24, 64, 32 },
                 { 39, 7, 47, 15, 55, 23, 63, 31 },
                 { 38, 6, 46, 14, 54, 22, 62, 30 },
                 { 37, 5, 45, 13, 53, 21, 61, 29 },
                 { 36, 4, 44, 12, 52, 20, 60, 28 },
                 { 35, 3, 43, 11, 51, 19, 59, 27 },
                 { 34, 2, 42, 10, 50, 18, 58, 26 },
                 { 33, 1, 41, 9, 49, 17, 57, 25  } };
        public override string Decrypt(string cipherText, string key)
        {
            // throw new NotImplementedException();

           

            string key_64 = Convert.ToString(Convert.ToInt64(key, 16), 2).PadLeft(64, '0');

            List<string> key1_shifted = new List<string>();
            List<string> key2_shifted = new List<string>();

            string key_56 = Permutaion(P_C_1, key_64, 8, 7);
            string key1 = key_56.Substring(0, 28);
            string key2 = key_56.Substring(28, 28);
            ShiftLeft(key1_shifted, key2_shifted, key2, key1);
            List<string> keys_56 = new List<string>();
            int i = 0;
            while (i < key2_shifted.Count)
            {
                keys_56.Add(key1_shifted[i] + key2_shifted[i]);
                i++;
            }
            List<string> keys_16 = round(keys_56);

            keys_16 = Enumerable.Reverse(keys_16).ToList();

            string cipher_64 = Convert.ToString(Convert.ToInt64(cipherText, 16), 2).PadLeft(64, '0');
            string cipher_56 = Permutaion(Init_Permutation, cipher_64, 8, 8);

            List<string> Left = new List<string>();
            List<string> Right = new List<string>();

            string l_plain = cipher_56.Substring(0, 32);
            string r_plain = cipher_56.Substring(32, 32);

            Left.Add(l_plain);
            Right.Add(r_plain);
            List<string> Sep_plain = new List<string>();

            for (int n = 0; n < 16; n++)
            {
                Left.Add(r_plain);
                Sep_plain.Clear();
                string plain_48 = Permutaion(Exp_Permutation, r_plain, 8, 6);
                string XoR = "";
                for (int j = 0; j < plain_48.Length; j++)
                {
                    XoR += (keys_16[n][j] ^ plain_48[j]).ToString();
                }
                for (int w = 0; w < XoR.Length; w += 6)
                {
                    string tmp = "";
                    for (int o = w; o < w + 6; o++)
                    {
                        tmp += XoR[o];
                    }
                    Sep_plain.Add(tmp);
                }
                string sbox_result = Sub_BOXES(Sep_plain);

                string last_permute_lp = Permutaion(Permute, sbox_result, 8, 4);
                XoR = "";
                for (int k = 0; k < last_permute_lp.Length; k++)
                {
                    XoR += (last_permute_lp[k] ^ l_plain[k]).ToString();
                }
                l_plain = r_plain;
                r_plain = XoR;
                Right.Add(r_plain);
            }
            string res = Right[16] + Left[16];

            string Cipher_Text = Permutaion(Init_Permutation_inverse, res, 8, 8);

            string C_T = Convert.ToInt64(Cipher_Text, 2).ToString("X").PadLeft(16, '0');

            return "0x" + C_T;
        }

        public override string Encrypt(string plainText, string key)
        {
            // throw new NotImplementedException();


            //hna b7wl elplaintext elli 3obara 3n hexadecimal l 64 bits mn zeros
            //w ones w elapd left dy bt7otly sefr 3lshemal 3shan tkml b2eet elbits lw 3adadha msh 64
            long block_OF_plaintext = Convert.ToInt64(plainText, 16);
            string plaincompleted = Convert.ToString(block_OF_plaintext, 2).PadLeft(64, '0');

            //nfs elhaga b3mlha llkey
            long block_OF_key = Convert.ToInt64(key, 16);
            string keycompleted = Convert.ToString(block_OF_key, 2).PadLeft(64, '0');

            //hna b2sm elcode l left w right
            string Left = "";
            string Right = "";
            int n = plaincompleted.Length / 2;
            for (int i = 0; i < n; i++)
            {
                Left += plaincompleted[i];
                Right += plaincompleted[i + n];
            }
            //da permutation llpermtable elli hwa pc_1 flpdf
            //elpermutation hna hykhli elkey mn 64 bits lhd 56 bits w y7othm f variable esmo permutate1 elli hwa esmo K flpdf
            string permutate1 = "";

            int[,] permutationtable = new int[8, 7] {
                { 57, 49, 41, 33, 25, 17, 9 },
                { 1, 58, 50, 42, 34, 26, 18 },
                { 10, 2, 59, 51, 43, 35, 27 },
                { 19, 11, 3, 60, 52, 44, 36 },
                { 63, 55, 47, 39, 31, 23, 15 },
                { 7, 62, 54, 46, 38, 30, 22 },
                { 14, 6, 61, 53, 45, 37, 29 },
                { 21, 13, 5, 28, 20, 12, 4 }
            };
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 7; j++)
                {
                    permutate1 += keycompleted[permutationtable[i, j] - 1];
                }
            }

            //3ndna hna list C w D htakhod string s elli hwa bad2 mn awl 28 bits fvariable elpermutate1
            //w el D htakhod akhr 28 y3ni mn awl 28 lhd 56 t2reebn y3ni
            string c0 = permutate1.Substring(0, 28);
            string d0 = permutate1.Substring(28);
            List<string> C = new List<string>();
            List<string> D = new List<string>();
            //ana hna kol shwaya b3ml shift bm3na eni kol shwaya hbtdy akhod mn elli abli w a7oto flC aw elD elli b3di w hakaza dy fkrt elshift
            //y3ni msln C3 w D3 htakhod mn elbits bta3tha mn elC2 w D2 w hakaza
            C.Add(c0);
            D.Add(d0);

            for (int i = 1; i <= 16; i++)
            {
                int shiftAmount = i == 1 || i == 2 || i == 9 || i == 16 ? 1 : 2;

                c0 = c0.Substring(shiftAmount) + c0.Substring(0, shiftAmount);
                d0 = d0.Substring(shiftAmount) + d0.Substring(0, shiftAmount);

                C.Add(c0);
                D.Add(d0);
            }
            //w kol qeema gdeda h7otha flK 3shan tgm3hom kolhm b2a y3ni K1 htb2a feha c1+d1 w kda
            List<string> collect_Key = new List<string>();
            for (int i = 0; i < D.Count; i++)
            {
                collect_Key.Add(C[i] + D[i]);
            }
            List<string> elnateg = new List<string>();
            //Bgenerate mn awl k1 lhd k16 3n taree2 permtable 2 elli hwa fl lab pc_2 mn 56 l 48 bits
            int[,] permutationTable2 = new int[8, 6] {
                { 14, 17, 11, 24, 1, 5 },
                { 3, 28, 15, 6, 21, 10 },
                { 23, 19, 12, 4, 26, 8 },
                { 16, 7, 27, 20, 13, 2 },
                { 41, 52, 31, 37, 47, 55 },
                { 30, 40, 51, 45, 33, 48 },
                { 44, 49, 39, 56, 34, 53 },
                { 46, 42, 50, 36, 29, 32 }
            };

            for (int k = 1; k < collect_Key.Count; k++)
            {
                string tempiono = collect_Key[k];
                StringBuilder tmpkBuilder = new StringBuilder();

                for (int i = 0; i < 8; i++)
                {
                    for (int j = 0; j < 6; j++)
                    {
                        tmpkBuilder.Append(tempiono[permutationTable2[i, j] - 1]);
                    }
                }

                elnateg.Add(tmpkBuilder.ToString());
            }


            int[,] IP = new int[8, 8] {
                { 58, 50, 42, 34, 26, 18, 10, 2 },
                { 60, 52, 44, 36, 28, 20, 12, 4 },
                { 62, 54, 46, 38, 30, 22, 14, 6 },
                { 64, 56, 48, 40, 32, 24, 16, 8 },
                { 57, 49, 41, 33, 25, 17, 9, 1 },
                { 59, 51, 43, 35, 27, 19, 11, 3 },
                { 61, 53, 45, 37, 29, 21, 13, 5 },
                { 63, 55, 47, 39, 31, 23, 15, 7 } };


            string iP = "";
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    iP += plaincompleted[IP[i, j] - 1];
                }
            }
            //w hna b2sm b2a el ip lnoseen 

            string small_left = iP.Substring(0, 32);
            string small_right = iP.Substring(32, 32);
            List<string> Left2 = new List<string>();
            List<string> Right2 = new List<string>();

            

            Left2.Add(small_left);
            Right2.Add(small_right);
            string st1 = "";
            string st2 = "";

            string eb = "";
            string ex = "";
            List<string> sbox = new List<string>();
            //string sb = "";
            string ziad = "";
            int row = 0;
            int col = 0;
            string tsb = "";
            string pp = "";
            string lf = "";

            int[,] EB = new int[8, 6] {
                { 32, 1, 2, 3, 4, 5 },
                { 4, 5, 6, 7, 8, 9 },
                { 8, 9, 10, 11, 12, 13 },
                { 12, 13, 14, 15, 16, 17 },
                { 16, 17, 18, 19, 20, 21 },
                { 20, 21, 22, 23, 24, 25 },
                { 24, 25, 26, 27, 28, 29 },
                { 28, 29, 30, 31, 32, 1 }
            };
            int N = 0;
            while ( N < 16)
            {
                Left2.Add(small_right);
                ex = "";
                eb = "";
                lf = "";
                pp = "";
                sbox.Clear();
                tsb = "";
                col = 0;
                row = 0;
                ziad = "";
                for (int j = 0; j < 8; j++)
                {
                    for (int k = 0; k < 6; k++)
                    {
                        eb = eb + small_right[EB[j, k] - 1];
                    }
                }

                for (int g = 0; g < eb.Length; g++)
                {
                    ex = ex + (elnateg[N][g] ^ eb[g]).ToString();
                }
                int z = 0;
                while ( z < ex.Length )
                {
                    ziad = "";
                    for (int y = z; y < 6 + z; y++)
                    {
                        if (6 + z <= ex.Length)
                            ziad = ziad + ex[y];
                    }

                    sbox.Add(ziad);
                    z = z + 6;
                }

                ziad = "";
                int sb = 0;
                int[,] s1 = new int[4, 16]
                {
                    { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 },
                    { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 },
                    { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 },
                    { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 }
                };
                int[,] s2 = new int[4, 16] {
                    { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 },
                    { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 },
                    { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 },
                    { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 }
                };
                int[,] s3 = new int[4, 16] { { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 },
                                             { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 },
                                             { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 },
                                             { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 }
                };
                int[,] s4 = new int[4, 16] {
                    { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 },
                    { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 },
                    { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 },
                    { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 }
                };
                int[,] s5 = new int[4, 16] {
                    { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 },
                    { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 },
                    { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 },
                    { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 }
                };
                int[,] s6 = new int[4, 16] {
                    { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 },
                    { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 },
                    { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 },
                    { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 }
                };
                int[,] s7 = new int[4, 16] {
                    { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 },
                    { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 },
                    { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 },
                    { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 }
                };
                int[,] s8 = new int[4, 16] {
                    { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 },
                    { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 },
                    { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 },
                    { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 }
                };


                int s = 0;

                while ( s < sbox.Count)
                {
                    ziad = sbox[s];
                    st1 = ziad[0].ToString() + ziad[5];
                    st2 = ziad[1].ToString() + ziad[2] + ziad[3] + ziad[4];

                    row = Convert.ToInt32(st1, 2);
                    col = Convert.ToInt32(st2, 2);

                    switch (s)
                    {
                        case 0:
                            sb = s1[row, col];
                            break;
                        case 1:
                            sb = s2[row, col];
                            break;
                        case 2:
                            sb = s3[row, col];
                            break;
                        case 3:
                            sb = s4[row, col];
                            break;
                        case 4:
                            sb = s5[row, col];
                            break;
                        case 5:
                            sb = s6[row, col];
                            break;
                        case 6:
                            sb = s7[row, col];
                            break;
                        case 7:
                            sb = s8[row, col];
                            break;
                    }

                    tsb = tsb + Convert.ToString(sb, 2).PadLeft(4, '0');
                    s++;
                }

                st1 = "";
                st2 = "";
                int[,] P = new int[8, 4] {
                    { 16, 7, 20, 21 },
                    { 29, 12, 28, 17 },
                    { 1, 15, 23, 26 },
                    { 5, 18, 31, 10 },
                    { 2, 8, 24, 14 },
                    { 32, 27, 3, 9 },
                    { 19, 13, 30, 6 },
                    { 22, 11, 4, 25 } };

                for (int k = 0; k < 8; k++)
                {
                    for (int j = 0; j < 4; j++)
                    {
                        pp = pp + tsb[P[k, j] - 1];
                    }
                }

                for (int k = 0; k < pp.Length; k++)
                {
                    lf = lf + (pp[k] ^ small_left[k]).ToString();
                }

                small_right = lf;
                small_left = Left2[N + 1];
                Right2.Add(small_right);
                N++;
            }
            string r16l16 = Right2[16] + Left2[16];
            string cipher = "";
            int[,] IP_1 = new int[8, 8] {
                { 40, 8, 48, 16, 56, 24, 64, 32 },
                { 39, 7, 47, 15, 55, 23, 63, 31 },
                { 38, 6, 46, 14, 54, 22, 62, 30 },
                { 37, 5, 45, 13, 53, 21, 61, 29 },
                { 36, 4, 44, 12, 52, 20, 60, 28 },
                { 35, 3, 43, 11, 51, 19, 59, 27 },
                { 34, 2, 42, 10, 50, 18, 58, 26 },
                { 33, 1, 41, 9, 49, 17, 57, 25 }
            };


            int q = 0;
            while ( q < 8)
            {
                for (int u = 0; u < 8; u++)
                {
                    cipher = cipher + r16l16[IP_1[q, u] - 1];
                }
                q++;
            }
            string ct = "0x" + Convert.ToInt64(cipher, 2).ToString("X");

            return ct;




        }
    }
}
