/*
 *  Copyright 2021-2021 yggo Technologies and contributors.
 *
 *  此源代码的使用受 GNU AFFERO GENERAL PUBLIC LICENSE version 3 许可证的约束, 可以在以下链接找到该许可证.
 *  Use of this source code is governed by the GNU AGPLv3 license that can be found through the following link.
 *
 *  https://github.com/yggo/androidqq-sniffer/blob/main/LICENSE
 */

using DotNetty.Buffers;
using System.Text;

namespace YgAndroidQQSniffer.TLVParser
{
    [Attributes.TLVParser(0x17E)]
    // devLockInfo
    public class TLV17E : IParser
    {
        public string Parse(IByteBuffer value)
        {
            StringBuilder sb = new StringBuilder();

            byte[] verifyReason = value.ReadRemainingBytes();

            sb.Append(verifyReason.HexDump()).Append($" //[verifyReason: {Encoding.UTF8.GetString(verifyReason)}]").AppendLine();

            return sb.ToString();
        }
    }
}
