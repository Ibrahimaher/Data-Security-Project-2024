using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    public class ExtendedEuclid 
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="number"></param>
        /// <param name="baseN"></param>
        /// <returns>Mul inverse, -1 if no inv</returns>
        public int GetMultiplicativeInverse(int number, int baseN)
        {
          
            int x1 = 1 , x2 = 0 , x3 = baseN , y1 = 0 , y2 = 1 , y3 = number;
            int t1, t2, t3;

            while (true)
            {
                if(y3 == 0)
                {
                    return -1; // no inv
                }
                else if(y3==1)
                {
                    while (y2 < 0)
                    {
                        y2 += baseN;
                    }
                    return y2; // inv
                }
                int q = x3 / y3;

                t1 = x1 - (q * y1);
                t2 = x2 - (q * y2);
                t3 = x3 - (q * y3);


                x1 = y1;
                x2 = y2;
                x3 = y3;

                y1 = t1;
                y2 = t2;
                y3 = t3;
            }
        }
    }
}
