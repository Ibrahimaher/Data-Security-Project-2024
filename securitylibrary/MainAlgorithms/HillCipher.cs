using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class HillCipher : ICryptographicTechnique<List<int>, List<int>>
    {
        


        private List<int> MultiblyMatrix(List<List<int>> key, List<int> MatRow, int m)
        {
            List<int> result = new List<int>();
            foreach (List<int> keyRow in key)
            {
                int tmp = 0;
                for (int i = 0; i < m; i++)
                {
                    tmp += keyRow[i] * MatRow[i];
                }
                tmp %= 26;
                while (tmp < 0)
                    tmp += 26;
                result.Add(tmp);
            }
            return result;
        }
        private List<List<int>> generate_matrix(List<int> key, int m, bool iskey)
        {
            List<List<int>> result = new List<List<int>>();
            int rows = key.Count / m;

            if (iskey)
                rows = m;


            int index = 0;
            for (int i = 0; i < rows; i++)
            {
                List<int> row_elements = new List<int>();
                for (int j = 0; j < m; j++)
                {
                    row_elements.Add(key[index]);
                    index++;
                }
                result.Add(row_elements);
            }


            return result;
        }
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            int xx = 0;

            void fill(int[,] x, List<int> plain)
            {
                if (plain.Count == 28)
                {
                    xx = 1;
                }
            }
            List<int> temp = new List<int>();
            bool isEqual = false;



            int i = 0;
            do
            {
               
                
                  for (int j = 0; j < 26; j++)
                {
                  
                      for (int k = 0; k < 26; k++)
                    {


                         for (int l = 0; l < 26; l++)
                        {
                            temp = Encrypt(plainText, new List<int> { l, k, j, i });
                            isEqual = Enumerable.SequenceEqual(temp, cipherText);
                            if (isEqual == true)
                            {
                                return new List<int> { l, k, j, i };
                            }
                            else
                            {
                                continue;
                            }
                        }
                    }
                }


                i++;
            } while (i < 26);


            if (!isEqual)
                throw new InvalidAnlysisException();
            return temp;
        }
        int Inverse_mat(int b)
        {
            int A1 = 1, A2 = 0, A3 = 26, B1 = 0, B2 = 1, B3 = b;
            double T1, T2, T3, Q;
            while (true)
            {
                switch (B3)
                {
                    case 0:
                        return -101;
                        break;
                    case 1:
                        return B2;
                        break;
                }
                Q = A3 / B3;
                     T1 = A1 - Q * B1;
                
                T2 = A2 - Q * B2;
                T3 = A3 - Q * B3;
                A1 = B1;

                A2 = B2;
                        A3 = B3;
          
                         B1 = (int)T1;
                B2 = (int)T2;
                B3 = (int)T3;
            }

        }
        List<int> Muti_matrix(int n, float[,] PlainText, int[,] CipherText)
        {

            double[,] key = new double[n, n];
            int i = 0;
            while (i < n)
            {
                int j = 0;
                while (j < n)
                {
                    key[i, j] = 0;
                    int k = 0;
                    while (k < n)
                    {

                        key[i, j] = key[i, j] + CipherText[i, k] * PlainText[k, j];
                        k++;
                    }
                    key[i, j] %= 26;
                    j++;
                }
                i++;
            }

            List<int> _NewKey = new List<int>();
            i = 0;
            while (i < n)
            {
                int j = 0;
                while (j < n)
                {
                    _NewKey.Add((int)key[i, j]);
                    j += 1;
                }
                i += 1;
            }
            return _NewKey;
        }
        //------------------
        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
             double Determinant_matrix(int m, int[,] keyMatrix)
            {

                int[,] _InnerMat = new int[m - 1, m - 1];
                double det = 0;
                switch (m)
                {
                    case 2:
                        return ((keyMatrix[0, 0] * keyMatrix[1, 1]) - (keyMatrix[1, 0] * keyMatrix[0, 1]));
                        break;
                    case 3:
                        int k = 0;
                        while (k < m)
                        {
                            int InnerI = 0, i = 1;
                            for (; i < m;)
                            {
                                int InnerJ = 0, j = 0;
                                for (; j < m; j++)
                                {
                                    if (j == k)
                                    {
                                        continue;
                                    }
                                    _InnerMat[InnerI, InnerJ] = keyMatrix[i, j];
                                    InnerJ++;
                                }
                                InnerI += 1;
                                i += 1;
                            }
                            double res = Determinant_matrix(m - 1, _InnerMat);
                            double _powOp = (Math.Pow(-1, k) * keyMatrix[0, k] * res);
                            det = det + _powOp;
                            k++;
                        }
                        break;
                }
                return det;
            }

            int Greatest_common_divisor(int x)
            {
                int y = 26;
                while (x != 0 && y != 0)
                {
                    if (x > y)
                        x = x % y;
                    else
                        y = y % x;
                }
                int _desc = (x == 0 ? y : x);
                return _desc;

            }

            // List<int> key1 = new List<int>(key.Count);
            int _CSQ = Convert.ToInt32(Math.Sqrt(key.Count));
            int[,] _keyOfMat = new int[_CSQ, _CSQ];
            int _Count = 0;
            for (int i = 0; i < _CSQ;)
            {
                int j = 0;
                for (; j < _CSQ;)
                {
                    bool _con1 = (key[_Count] >= 0), _con2 = (key[_Count] <= 26);
                    if (_con1 && _con2)
                        _keyOfMat[i, j] = key[_Count++];
                    else if (key[_Count] > 26)
                    {
                        int x = key[_Count];
                        x = x % 26;
                        _keyOfMat[i, j] = x;
                        _Count++;
                    }
                    else
                    {
                        break;
                    }
                    j += 1;
                }
                i += 1;
            }
            double _OutRes = Determinant_matrix(_CSQ, _keyOfMat);
            _OutRes = _OutRes % 26;
            if (_OutRes < 0)
                _OutRes = _OutRes + 26;

            int _GcdRes = Greatest_common_divisor((int)_OutRes);
            //TESTCASE : HillCipherError3
            // No common factors between det(k) and 26(GCD(26, det(k)) = 1)

            if (_GcdRes != 1)
                throw new Exception();

            if (_CSQ == 2)
            {
                float _theInv = 0;
                float A, B, C, D;
                A = (_keyOfMat[0, 0]);
                B = (_keyOfMat[0, 1]);
                C = (_keyOfMat[1, 0]);
                D = (_keyOfMat[1, 1]);
                _theInv = 1 / ((A * D) - (B * C));
                A = A * _theInv; D = D * _theInv;
                B = B * _theInv * -1; C = C * _theInv * -1;
                key[0] = (int)D;
                key[1] = (int)B;
                key[2] = (int)C;
                key[3] = (int)A;
                return Encrypt(cipherText, key);
            }
            double c = 0, b = 0, d = 26 - _OutRes; _Count = 1;
            for (int i = 0; i < cipherText.Count; i++)
            {
                int _InnerOp = (26 * _Count + 1);
                double _theInncon = _InnerOp % d;
                if (_theInncon != 0)
                    _Count += 1;
                else
                    break;
            }
            c = (26 * _Count + 1) / d;
            b = 26 - c;
            int[,] _theInnerMat = new int[_CSQ - 1, _CSQ - 1];
            double[,] keyMatrixOutput = new double[_CSQ, _CSQ];
            int Lenj = 0, Leni = 0;

            // loop el k de btlef 3l el row

            for (int i = 0; i < 3;)
            {
                int j = 0;
                while (j < 3)
                {
                    int II = 0, III = 0, x = 0;
                    for (; x < 3; x++)
                        for (int y = 0; y < 3;)
                        {
                            bool InCon3 = (x == i || y == j);
                            if (!InCon3)
                            {
                                _theInnerMat[II, III] = _keyOfMat[x, y];
                                III++;
                                II = II + (III / 2);
                                III %= 2;
                            }
                            y += 1;
                        }
                    double _theAnsPowD = (b * (Math.Pow(-1, (i + j)) * (Determinant_matrix(_CSQ - 1, _theInnerMat))) % 26);
                    if (_theAnsPowD < 0)
                        _theAnsPowD += 26;
                    keyMatrixOutput[Leni, Lenj] = _theAnsPowD;
                    Lenj += 1;
                    if (Lenj > 2)
                    {
                        Lenj = 0; Leni += 1;
                    }
                    j += 1;
                }
                i += 1;
            }
            int _R2 = keyMatrixOutput.GetLength(0), _C2 = keyMatrixOutput.GetLength(1);
            double[,] _FiRes = new double[_C2, _R2];
            for (int i = 0; i < _R2;)
            {
                int j = 0;
                while (j < _C2)
                {
                    _FiRes[j, i] = keyMatrixOutput[i, j];
                    j += 1;
                }
                i += 1;
            }
            keyMatrixOutput = _FiRes;
            _Count = 0;
            for (int i = 0; i < _CSQ;)
            {
                for (int j = 0; j < _CSQ;)
                {
                    key[_Count] = (int)keyMatrixOutput[i, j];
                    _Count++; j++;
                }
                i += 1;
            }
            List<int> _theFinalResult = Encrypt(cipherText, key);
            return _theFinalResult;
        }

        public double Determinant_matrix(int m, int[,] keyMatrix)
        {

            int[,] _InnerMat = new int[m - 1, m - 1];
            double det = 0;
            switch (m)
            {
                case 2:
                    return ((keyMatrix[0, 0] * keyMatrix[1, 1]) - (keyMatrix[1, 0] * keyMatrix[0, 1]));
                    break;
                case 3:
                    int k = 0;
                    while (k < m)
                    {
                        int InnerI = 0, i = 1;
                        for (; i < m;)
                        {
                            int InnerJ = 0, j = 0;
                            for (; j < m; j++)
                            {
                                if (j == k)
                                {
                                    continue;
                                }
                                _InnerMat[InnerI, InnerJ] = keyMatrix[i, j];
                                InnerJ++;
                            }
                            InnerI += 1;
                            i += 1;
                        }
                        double res = Determinant_matrix(m - 1, _InnerMat);
                        double _powOp = (Math.Pow(-1, k) * keyMatrix[0, k] * res);
                        det = det + _powOp;
                        k++;
                    }
                    break;
            }
            return det;
        }
        public double[,] Transpose(double[,] matrix)
        {
            int _R1 = matrix.GetLength(0);
            int _C1 = matrix.GetLength(1);

            double[,] result = new double[_C1, _R1];
            int i = 0;
            while (i < _R1)
            {
                int j = 0;
                while (j < _C1)
                {
                    result[i, j] = matrix[i, j];
                    j += 1;
                }
                i += 1;
            }

            return result;
        }

        private static int Greatest_common_divisor(int x)
        {
            int y = 26;
            while (x != 0 && y != 0)
            {
                if (x > y)
                    x = x % y;
                else
                    y = y % x;
            }
            int _desc = (x == 0 ? y : x);
            return _desc;


        }

     
  


        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            List<int> cipher_text = new List<int>();
            int n = (int)Math.Sqrt(key.Count);

            List<List<int>> plain_mat = generate_matrix(plainText, n, false);

            List<List<int>> keymatarix = generate_matrix(key, n, true);

            int i = 0;
            while (i < plainText.Count / n)
            {
                List<int> tmp = MultiblyMatrix(keymatarix, plain_mat[i], n);
                int j = 0;
                while (j < n)
                {
                    cipher_text.Add(tmp[j]);
                    j++;
                }
                i++;
            }
            return cipher_text;
        }
            
            public List<int> Analyse3By3Key(List<int> plainText, List<int> cipherText)
        {
            int Ln = 0;

            int PltSq = (int)Math.Sqrt(plainText.Count);
            double[,] tCipherTMat = new double[PltSq, PltSq];
            int l = 0;
            while (l < PltSq)
            {
                int j = 0;
                while (j < PltSq)
                {
                    bool _cond1 = (cipherText[Ln] >= 0) && (cipherText[Ln] <= 26), _cond2 = cipherText[Ln] > 26;
                    if (_cond1)
                        tCipherTMat[j, l] = cipherText[Ln++];
                    else if (_cond2)
                    {
                        int x = cipherText[Ln];
                        x = x % 26;
                        tCipherTMat[j, l] = x;
                        Ln += 1;
                    }
                    else
                    {
                        break;
                    }
                    j += 1;
                }
                l += 1;
            }

            int[,] tPlainTMat = new int[PltSq, PltSq];
            Ln = 0;
            for (int i = 0; i < PltSq; i++)
            {
                int j = 0;
                while (j < PltSq)
                {
                    bool _condi1 = (plainText[Ln] >= 0) && (plainText[Ln] <= 26), _condi2 = plainText[Ln] > 26;
                    if (_condi1)
                        tPlainTMat[i, j] = plainText[Ln++];
                    else if (_condi2)
                    {
                        int x = plainText[Ln];
                        x %= 26;
                        tPlainTMat[i, j] = x;
                        Ln++;
                    }
                    else
                    {
                        break;
                    }
                    j += 1;
                }
            }
            double tMPl = Determinant_matrix(PltSq, tPlainTMat);

            tMPl = tMPl % 26;
            if (tMPl < 0)
                tMPl = tMPl + 26;
            int _theGcdPl = Greatest_common_divisor((int)tMPl);
            if (_theGcdPl != 1)
                throw new Exception();
            double c = 0, b = 0, d = 26 - tMPl;
            Ln = 1;
            for (int i = 0; i < plainText.Count; i++)
            {
                int ConRes1 = (26 * Ln + 1);
                double ConR = ConRes1 % d;
                if (ConR != 0)
                    Ln++;
                else
                    break;
            }
            c = (26 * Ln + 1) / d; b = 26 - c;
            int[,] _MatOfSub = new int[PltSq - 1, PltSq - 1];
            double[,] _OuterMatPlainT = new double[PltSq, PltSq];
            int theOutJ = 0, theOutI = 0;

            for (int i = 0; i < 3;)
            {
                int j = 0;
                int v = 4;
                while (j < v - 1)
                {
                    int XX = 0;
                    int XOO = 0;

                    int z = 0;
                    for (; z < 3; z++)
                        for (int y = 0; y < 3;)
                        {
                            if (!(z == i || y == j))
                            {
                                _MatOfSub[XX, XOO] = tPlainTMat[z, y];
                                XOO++; XX = XX + (XOO / 2); XOO = XOO % 2;
                            }
                            y += 1;
                        }


                    double iRes = (b * (Math.Pow(-1, (i + j)) * Determinant_matrix(PltSq - 1, _MatOfSub)) % 26);


                    if (iRes < 0)
                        iRes += 26;
                    _OuterMatPlainT[theOutI, theOutJ] = iRes;
                    theOutJ++;
                    if (theOutJ > 2)
                    {
                        theOutJ = 0;
                        theOutI += 1;
                    }
                    j += 1;
                }
                i += 1;
            }
            _OuterMatPlainT = Transpose(_OuterMatPlainT);
            int Cln = (int)Math.Sqrt(cipherText.Count);
            double[,] key = new double[PltSq, Cln];
            for (int i = 0; i < 3; i++)
            {
                int j = 0;
                for (; j < PltSq;)
                {
                    key[i, j] = 0; int k = 0;
                    while (k < PltSq)
                    {

                        key[i, j] = key[i, j] + (tCipherTMat[j, k] * _OuterMatPlainT[k, i]);
                        key[i, j] = key[i, j] % 26;
                        k += 1;
                    }
                    j += 1;
                }
            }
            List<int> KeyValues = new List<int>(9);


            for (int z = 0; z < 3; z++)

            {

                for (int j = 0; j < 3; j++)
                {
                    KeyValues.Add((int)key[j, z]);
                }
            }
            return KeyValues;
        }
    }
}