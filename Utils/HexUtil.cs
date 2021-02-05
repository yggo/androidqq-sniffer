/*
 *  Copyright 2021-2021 yggo Technologies and contributors.
 *
 *  此源代码的使用受 GNU AFFERO GENERAL PUBLIC LICENSE version 3 许可证的约束, 可以在以下链接找到该许可证.
 *  Use of this source code is governed by the GNU AGPLv3 license that can be found through the following link.
 *
 *  https://github.com/yggo/androidqq-sniffer/blob/main/LICENSE
 */

using System;
using System.Text.RegularExpressions;

namespace YgAndroidQQSniffer
{
    public static class HexUtil
    {
        public static byte[] DecodeHex(this string hexStr)
        {
            if (string.IsNullOrEmpty(hexStr))
            {
                throw new ArgumentNullException("字节数据不能为空或null");
            }
            hexStr = hexStr.ClearSpecialSymbols();
            if ((hexStr.Length % 2) != 0)
            {
                hexStr += "";
            }
            if (!Regex.IsMatch(hexStr, "^[0-9a-fA-F]+$"))
            {
                throw new ArgumentException("非法的16进制字节数据");
            }
            byte[] returnBytes = new byte[hexStr.Length / 2];
            for (int i = 0; i < returnBytes.Length; i++)
            {
                returnBytes[i] = Convert.ToByte(hexStr.Substring(i * 2, 2), 16);
            }
            return returnBytes;
        }
    }
}
