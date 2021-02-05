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
    [Attributes.TLVParser(0x17D)]
    public class TLV17D : IParser
    {
        public string Parse(IByteBuffer value)
        {
            StringBuilder sb = new StringBuilder();

            sb.Append(value.ReadShort().HexPadLeft().HexDump()).AppendLine();
            sb.Append(value.ReadInt().HexPadLeft().HexDump()).AppendLine();
            short url_len = value.ReadShort();
            sb.Append(url_len.HexPadLeft().HexDump()).Append($" //url_len={url_len}").AppendLine();
            byte[] url = value.ReadRemainingBytes();
            sb.Append(url.HexDump()).Append($" //[{Encoding.UTF8.GetString(url)}]").AppendLine();

            return sb.ToString();
        }
    }
}
