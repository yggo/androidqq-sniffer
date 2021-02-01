using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace YgAndroidQQSniffer.Extension
{
    public class MyDictionaryComparer : IEqualityComparer<short>
    {
        public bool Equals(short x, short y)
        {
            return x != y;
        }

        public int GetHashCode(short obj)
        {
            return obj.GetHashCode();
        }
    }
}
