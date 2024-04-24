using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class TripleDES : ICryptographicTechnique<string, List<string>>
    {

        public string Trible_Des_Decrypt(string cipherText, string key)
        {
            // This function takes a cipher text and a des_key as hexadecimal strings and returns the decrypted text

            // Pre-computed DES tables
            // Permutation Choice 2 table

            int[,] PerC2 = new int[8, 6] { { 14, 17, 11, 24, 1, 5 }, { 3, 28, 15, 6, 21, 10 }, { 23, 19, 12, 4, 26, 8 }, { 16, 7, 27, 20, 13, 2 }, { 41, 52, 31, 37, 47, 55 }, { 30, 40, 51, 45, 33, 48 }, { 44, 49, 39, 56, 34, 53 }, { 46, 42, 50, 36, 29, 32 } };
            // Permutation Choice 1 table



            int[,] PerC_1 = new int[8, 7] { { 57, 49, 41, 33, 25, 17, 9 }, { 1, 58, 50, 42, 34, 26, 18 }, { 10, 2, 59, 51, 43, 35, 27 }, { 19, 11, 3, 60, 52, 44, 36 }, { 63, 55, 47, 39, 31, 23, 15 }, { 7, 62, 54, 46, 38, 30, 22 }, { 14, 6, 61, 53, 45, 37, 29 }, { 21, 13, 5, 28, 20, 12, 4 } };


            int[,] P = new int[8, 4] { { 16, 7, 20, 21 }, { 29, 12, 28, 17 }, { 1, 15, 23, 26 }, { 5, 18, 31, 10 }, { 2, 8, 24, 14 }, { 32, 27, 3, 9 }, { 19, 13, 30, 6 }, { 22, 11, 4, 25 } };


            int[,] s1 = new int[4, 16] { { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 }, { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 }, { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 }, { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 } };

            int[,] s8 = new int[4, 16] { { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 }, { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 }, { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 }, { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } };


            int[,] s3 = new int[4, 16] { { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 }, { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 }, { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 }, { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 } };

            int[,] s5 = new int[4, 16] { { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 }, { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 }, { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 }, { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 } };


            int[,] s4 = new int[4, 16] { { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 }, { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 }, { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 }, { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 } };

            int[,] s6 = new int[4, 16] { { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 }, { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 }, { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 }, { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 } };
            int[,] s7 = new int[4, 16] { { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 }, { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 }, { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 }, { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 } };
            int[,] s2 = new int[4, 16] { { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 }, { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 }, { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 }, { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 } };


            int[,] EB = new int[8, 6] { { 32, 1, 2, 3, 4, 5 }, { 4, 5, 6, 7, 8, 9 }, { 8, 9, 10, 11, 12, 13 }, { 12, 13, 14, 15, 16, 17 }, { 16, 17, 18, 19, 20, 21 }, { 20, 21, 22, 23, 24, 25 }, { 24, 25, 26, 27, 28, 29 }, { 28, 29, 30, 31, 32, 1 } };

            int[,] IP = new int[8, 8] { { 58, 50, 42, 34, 26, 18, 10, 2 }, { 60, 52, 44, 36, 28, 20, 12, 4 }, { 62, 54, 46, 38, 30, 22, 14, 6 }, { 64, 56, 48, 40, 32, 24, 16, 8 }, { 57, 49, 41, 33, 25, 17, 9, 1 }, { 59, 51, 43, 35, 27, 19, 11, 3 }, { 61, 53, 45, 37, 29, 21, 13, 5 }, { 63, 55, 47, 39, 31, 23, 15, 7 } };

            int[,] IP_1 = new int[8, 8] { { 40, 8, 48, 16, 56, 24, 64, 32 }, { 39, 7, 47, 15, 55, 23, 63, 31 }, { 38, 6, 46, 14, 54, 22, 62, 30 }, { 37, 5, 45, 13, 53, 21, 61, 29 }, { 36, 4, 44, 12, 52, 20, 60, 28 }, { 35, 3, 43, 11, 51, 19, 59, 27 }, { 34, 2, 42, 10, 50, 18, 58, 26 }, { 33, 1, 41, 9, 49, 17, 57, 25 } };


            string biy_ciphers = Convert.ToString(Convert.ToInt64(cipherText, 16), 2).PadLeft(64, '0');
            string bikey = Convert.ToString(Convert.ToInt64(key, 16), 2).PadLeft(64, '0');

            string Lo = "";
            string Ro = "";

            for (int i = 0; i < biy_ciphers.Length / 2; i++)
            {
                Lo = Lo + biy_ciphers[i];
                Ro = Ro + biy_ciphers[i + biy_ciphers.Length / 2];
            }

            //premutate des_key by pc-1
            string tmpk = "";

            List<string> Coo = new List<string>();


            List<string> Dod = new List<string>();

            for (int i = 0; i < 8; i++)
            {
                //******
                int FF = 0;
                while (FF < 7)
                {

                    tmpk = tmpk + bikey[PerC_1[i, FF] - 1];
                    FF++;
                }
            }


            string dist = tmpk.Substring(28, 28);

            string temp = "";

            string cosin = tmpk.Substring(0, 28);

            for (int i = 0; i <= 16; i++)
            {
                Coo.Add(cosin);
                Dod.Add(dist);
                temp = "";
                Boolean sddd = true;
                void check()
                {
                    if (i == 0 || i == 1 || i == 8 || i == 15)
                        sddd = false;
                }
                if (i == 0 || i == 1 || i == 8 || i == 15)
                {
                    temp = temp + cosin[0];
                    cosin = cosin.Remove(0, 1);

                    cosin = cosin + temp;

                    temp = "";


                    temp = temp + dist[0];

                    dist = dist.Remove(0, 1);

                    dist = dist + temp;
                }

                else
                {
                    temp = temp + cosin.Substring(0, 2);
                    cosin = cosin.Remove(0, 2);


                    cosin = cosin + temp;
                    temp = "";
                    temp = temp + dist.Substring(0, 2);

                    dist = dist.Remove(0, 2);
                    dist = dist + temp;
                }
            }

            List<string> keys_of = new List<string>();


            for (int i = 0; i < Dod.Count; i++)
            {
                keys_of.Add(Coo[i] + Dod[i]);
            }


            List<string> nkeys = new List<string>();
            for (int k = 1; k < keys_of.Count; k++)
            {
                tmpk = "";
                temp = "";
                temp = keys_of[k];
                for (int i = 0; i < 8; i++)
                {
                    for (int j = 0; j < 6; j++)
                    {
                        tmpk = tmpk + temp[PerC2[i, j] - 1];
                    }
                }

                nkeys.Add(tmpk);
            }


            string ip = "";
            for (int i = 0; i < 8; i++)
            {
                int toz = 0;
                while (toz < 8)
                {

                    ip = ip + biy_ciphers[IP[i, toz] - 1];
                    toz++;
                }
            }
            List<string> R = new List<string>();



            List<string> Lor = new List<string>();

            string l = ip.Substring(0, 32);
            string r = ip.Substring(32, 32);

            Lor.Add(l);
            R.Add(r);
            string x = "";
            string h = "";

            string ebitsso = "";
            string exorkss = "";
            List<string> sbox = new List<string>();

            string t = "";

            int row = 0;
            int col = 0;

            string lf = "";


            string tsb = "";
            string pp = "";


            for (int i = 0; i < 16; i++)
            {
                Lor.Add(r);
                exorkss = "";
                ebitsso = "";
                lf = "";
                pp = "";
                sbox.Clear();
                tsb = "";
                col = 0;
                row = 0;
                t = "";
                for (int j = 0; j < 8; j++)
                {
                    for (int k = 0; k < 6; k++)
                    {
                        ebitsso = ebitsso + r[EB[j, k] - 1];
                    }
                }

                for (int g = 0; g < ebitsso.Length; g++)
                {
                    exorkss = exorkss + (nkeys[nkeys.Count - 1 - i][g] ^ ebitsso[g]).ToString();
                }

                for (int z = 0; z < exorkss.Length; z = z + 6)
                {
                    t = "";
                    for (int y = z; y < 6 + z; y++)
                    {
                        void coc(Boolean fff)
                        {
                            if (6 + z <= exorkss.Length)
                                fff = true;
                        }
                        if (6 + z <= exorkss.Length)
                            t = t + exorkss[y];
                        Boolean xc = true;
                    }

                    sbox.Add(t);
                }

                t = " ";
                int sb = 0;
                for (int s = 0; s < sbox.Count; s++)
                {
                    t = sbox[s];
                    x = t[0].ToString() + t[5];
                    h = t[1].ToString() + t[2] + t[3] + t[4];

                    row = Convert.ToInt32(x, 2);
                    col = Convert.ToInt32(h, 2);
                    if (s == 0)
                        sb = s1[row, col];

                    if (s == 1)
                        sb = s2[row, col];

                    if (s == 2)
                        sb = s3[row, col];

                    if (s == 3)
                        sb = s4[row, col];

                    if (s == 4)
                        sb = s5[row, col];

                    if (s == 5)
                        sb = s6[row, col];

                    if (s == 6)
                        sb = s7[row, col];

                    if (s == 7)
                        sb = s8[row, col];

                    tsb = tsb + Convert.ToString(sb, 2).PadLeft(4, '0');
                }

                x = "";
                h = "";

                for (int k = 0; k < 8; k++)
                {
                    int j = 0;
                    while (j < 4)
                    {
                        pp = pp + tsb[P[k, j] - 1];


                        j++;
                    }
                }

                for (int k = 0; k < pp.Length; k++)
                {
                    lf = lf + (pp[k] ^ l[k]).ToString();
                }

                r = lf;
                l = Lor[i + 1];
                R.Add(r);
            }

            string r16l = R[16] + Lor[16];
            string ciphertxt = "";
            for (int i = 0; i < 8; i++)
            {
                int j = 0;
                while (j < 8)
                {

                    ciphertxt = ciphertxt + r16l[IP_1[i, j] - 1];
                    j++;
                }
            }
            string plain_text = "0x" + Convert.ToInt64(ciphertxt, 2).ToString("X").PadLeft(16, '0');
            return plain_text;
        }

        public string DesEncrypt(string plainText, string des_key)
        {
            int[,] s1 = new int[4, 16] { { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 }, { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 }, { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 }, { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 } };


            int[,] PC_1 = new int[8, 7] { { 57, 49, 41, 33, 25, 17, 9 }, { 1, 58, 50, 42, 34, 26, 18 }, { 10, 2, 59, 51, 43, 35, 27 }, { 19, 11, 3, 60, 52, 44, 36 }, { 63, 55, 47, 39, 31, 23, 15 }, { 7, 62, 54, 46, 38, 30, 22 }, { 14, 6, 61, 53, 45, 37, 29 }, { 21, 13, 5, 28, 20, 12, 4 } };

            int[,] s6 = new int[4, 16] { { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 }, { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 }, { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 }, { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 } };
            int[,] s12 = new int[4, 16] { { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 }, { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 }, { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 }, { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 } };


            int[,] s2 = new int[4, 16] { { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 }, { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 }, { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 }, { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 } };

            int[,] PC_2 = new int[8, 6] { { 14, 17, 11, 24, 1, 5 }, { 3, 28, 15, 6, 21, 10 }, { 23, 19, 12, 4, 26, 8 }, { 16, 7, 27, 20, 13, 2 }, { 41, 52, 31, 37, 47, 55 }, { 30, 40, 51, 45, 33, 48 }, { 44, 49, 39, 56, 34, 53 }, { 46, 42, 50, 36, 29, 32 } };




            int[,] s3 = new int[4, 16] { { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 }, { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 }, { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 }, { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 } };
            int[,] s4 = new int[4, 16] { { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 }, { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 }, { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 }, { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 } };
            int[,] s5 = new int[4, 16] { { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 }, { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 }, { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 }, { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 } };
            int[,] s7 = new int[4, 16] { { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 }, { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 }, { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 }, { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 } };
            int[,] s8 = new int[4, 16] { { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 }, { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 }, { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 }, { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } };

            int[,] P = new int[8, 4] { { 16, 7, 20, 21 }, { 29, 12, 28, 17 }, { 1, 15, 23, 26 }, { 5, 18, 31, 10 }, { 2, 8, 24, 14 }, { 32, 27, 3, 9 }, { 19, 13, 30, 6 }, { 22, 11, 4, 25 } };

            int[,] EB = new int[8, 6] { { 32, 1, 2, 3, 4, 5 }, { 4, 5, 6, 7, 8, 9 }, { 8, 9, 10, 11, 12, 13 }, { 12, 13, 14, 15, 16, 17 }, { 16, 17, 18, 19, 20, 21 }, { 20, 21, 22, 23, 24, 25 }, { 24, 25, 26, 27, 28, 29 }, { 28, 29, 30, 31, 32, 1 } };

            int[,] IP = new int[8, 8] { { 58, 50, 42, 34, 26, 18, 10, 2 }, { 60, 52, 44, 36, 28, 20, 12, 4 }, { 62, 54, 46, 38, 30, 22, 14, 6 }, { 64, 56, 48, 40, 32, 24, 16, 8 }, { 57, 49, 41, 33, 25, 17, 9, 1 }, { 59, 51, 43, 35, 27, 19, 11, 3 }, { 61, 53, 45, 37, 29, 21, 13, 5 }, { 63, 55, 47, 39, 31, 23, 15, 7 } };

            int[,] IP_1 = new int[8, 8] { { 40, 8, 48, 16, 56, 24, 64, 32 }, { 39, 7, 47, 15, 55, 23, 63, 31 }, { 38, 6, 46, 14, 54, 22, 62, 30 }, { 37, 5, 45, 13, 53, 21, 61, 29 }, { 36, 4, 44, 12, 52, 20, 60, 28 }, { 35, 3, 43, 11, 51, 19, 59, 27 }, { 34, 2, 42, 10, 50, 18, 58, 26 }, { 33, 1, 41, 9, 49, 17, 57, 25 } };


            string bikeyss = Convert.ToString(Convert.ToInt64(des_key, 16), 2).PadLeft(64, '0');

            string Lms = "";
            string biplainss = Convert.ToString(Convert.ToInt64(plainText, 16), 2).PadLeft(64, '0');


            string Rmssoo = "";

            int ffuu = biplainss.Length / 2;
            for (int i = 0; i < ffuu; i++)
            {
                Lms = Lms + biplainss[i];
                Rmssoo = Rmssoo + biplainss[i + ffuu];
            }
            List<string> Cods = new List<string>();

            //premutate des_key by pc-1
            string tmpk = "";

            List<string> Dos = new List<string>();

            for (int i = 0; i < 8; i++)
            {
                int j = 0;
                while (j < 7)
                {
                    tmpk = tmpk + bikeyss[PC_1[i, j] - 1];


                    j++;
                }
            }

            string d = tmpk.Substring(28, 28);

            //Coo and Dod
            string c = tmpk.Substring(0, 28);

            int azb = 5;
            string temp = "";
            for (int i = 0; i < 17 + 2 + 1 + 2 - azb; i++)
            {
                Cods.Add(c);
                Dos.Add(d);
                temp = "";
                if (i == 0 || i == 1 || i == 8 || i == 15)
                {
                    temp = temp + c[0];

                    c = c.Remove(0, 1);
                    c = c + temp;

                    temp = "";


                    temp = temp + d[0];
                    d = d.Remove(0, 1);
                    d = d + temp;
                }

                else
                {

                    temp = temp + c.Substring(0, 2);
                    c = c.Remove(0, 2);

                    c = c + temp;
                    temp = "";

                    temp = temp + d.Substring(0, 2);



                    d = d.Remove(0, 2);
                    d = d + temp;
                }
            }

            List<string> des_keys = new List<string>();
            int iso = 0;
            while (iso < Dos.Count)
            {
                des_keys.Add(Cods[iso] + Dos[iso]);
                iso++;
            }

            List<string> n_deskeys = new List<string>();


            for (int k = 1; k < des_keys.Count; k++)
            {
                tmpk = "";
                temp = "";
                temp = des_keys[k];
                for (int i = 0; i < 8; i++)
                {
                    int j = 0;
                    while (j < 6)
                    {
                        tmpk = tmpk + temp[PC_2[i, j] - 1];
                        j++;
                    }

                }

                n_deskeys.Add(tmpk);
            }



            string ips = "";


            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    ips = ips + biplainss[IP[i, j] - 1];
                }
            }

            List<string> Lod = new List<string>();
            List<string> Rod = new List<string>();

            string l = ips.Substring(0, 32);
            string r = ips.Substring(32, 32);

            Lod.Add(l);
            Rod.Add(r);
            string ebit = "";

            string xor = "";
            string hss = "";



            string exork = "";
            List<string> sbox = new List<string>();
            //string sb = "";
            string t = "";
            int row = 0;
            int col = 0;
            string tsb = "";
            string pp = "";


            string lf = "";

            for (int i = 0; i < 16; i++)
            {
                Lod.Add(r);
                exork = "";
                ebit = "";
                lf = "";
                pp = "";
                sbox.Clear();
                tsb = "";
                col = 0;
                row = 0;
                t = "";
                for (int j = 0; j < 8; j++)
                {
                    int k = 0;
                    while (k < 6)
                    {
                        ebit = ebit + r[EB[j, k] - 1];
                        k++;
                    }
                }

                int g = 0;
                while (g < ebit.Length)
                {
                    exork = exork + (n_deskeys[i][g] ^ ebit[g]).ToString();
                    g++;
                }

                for (int z = 0; z < exork.Length; z = z + 6)
                {
                    t = "";
                    for (int y = z; y < 6 + z; y++)
                    {
                        void checkas()
                        {
                            int x = 0;
                            x += z + g;

                        }

                        if (6 + z + 2 - 2 <= exork.Length)
                            t = t + exork[y];
                    }

                    sbox.Add(t);
                }

                t = "";
                int sb = 0;
                for (int s = 0; s < sbox.Count; s++)
                {
                    t = sbox[s];
                    xor = t[0].ToString() + t[5];
                    hss = t[1].ToString() + t[2] + t[3] + t[4];

                    row = Convert.ToInt32(xor, 2);
                    col = Convert.ToInt32(hss, 2);
                    if (s == 0)
                        sb = s1[row, col];

                    if (s == 1)
                        sb = s2[row, col];

                    if (s == 5)
                        sb = s6[row, col];

                    if (s == 6)
                        sb = s7[row, col];

                    if (s == 7)
                        sb = s8[row, col];

                    if (s == 2)
                        sb = s3[row, col];

                    if (s == 3)
                        sb = s4[row, col];

                    if (s == 4)
                        sb = s5[row, col];

                    tsb = tsb + Convert.ToString(sb, 2).PadLeft(4, '0');
                }

                xor = "";
                hss = "";

                for (int k = 0; k < 8; k++)
                {
                    int j = 0;
                    while (j < 4)
                    {
                        pp = pp + tsb[P[k, j] - 1];
                        j++;
                    }
                }

                for (int k = 0; k < pp.Length; k++)
                {
                    lf = lf + (pp[k] ^ l[k]).ToString();
                }

                r = lf;
                l = Lod[i + 1];
                Rod.Add(r);
            }

            string r16l16 = Rod[16] + Lod[16];
            string ciphertxt = "";
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    ciphertxt = ciphertxt + r16l16[IP_1[i, j] - 1];
                }
            }

            string x01 = "0x";
            string ctext = x01 + Convert.ToInt64(ciphertxt, 2).ToString("X");

            return ctext;
        }


        public string Decrypt(string cipherText, List<string> key)
        {
            string plain_text = "";

            plain_text = Trible_Des_Decrypt(cipherText, key[1]);
            plain_text = DesEncrypt(plain_text, key[0]);
            plain_text = Trible_Des_Decrypt(plain_text, key[1]);

            return plain_text;

            throw new NotImplementedException();
        }

        public string Encrypt(string plainText, List<string> key)
        {
            string ctext = "";

            ctext = DesEncrypt(plainText, key[0]);
            ctext = Trible_Des_Decrypt(ctext, key[1]);
            ctext = DesEncrypt(ctext, key[0]);

            return ctext;
            throw new NotImplementedException();
        }

        public List<string> Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }

    }
}