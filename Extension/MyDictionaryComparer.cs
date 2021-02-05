/*
 *  Copyright 2021-2021 yggo Technologies and contributors.
 *
 *  此源代码的使用受 GNU AFFERO GENERAL PUBLIC LICENSE version 3 许可证的约束, 可以在以下链接找到该许可证.
 *  Use of this source code is governed by the GNU AGPLv3 license that can be found through the following link.
 *
 *  https://github.com/yggo/androidqq-sniffer/blob/main/LICENSE
 */

using System.Collections.Generic;

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
