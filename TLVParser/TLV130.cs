/*
 *  Copyright 2021-2021 yggo Technologies and contributors.
 *
 *  此源代码的使用受 GNU AFFERO GENERAL PUBLIC LICENSE version 3 许可证的约束, 可以在以下链接找到该许可证.
 *  Use of this source code is governed by the GNU AGPLv3 license that can be found through the following link.
 *
 *  https://github.com/yggo/androidqq-sniffer/blob/main/LICENSE
 */

using DotNetty.Buffers;
using System;
using System.Text;

namespace YgAndroidQQSniffer.TLVParser
{
    [Attributes.TLVParser(0x130)]
    public class TLV130 : IParser
    {
        public string Parse(IByteBuffer value)
        {
            StringBuilder sb = new StringBuilder();

            value.ReadShort();
            uint timestamp = value.ReadUnsignedInt();
            uint ip = value.ReadUnsignedIntLE();

            DateTime login_time = Util.HexToDateTime(timestamp);
            string login_ip = Util.LongToIp(ip);

            sb.Append("00").AppendLine();
            sb.Append(timestamp.HexPadLeft().HexDump()).Append($" //[Time: {login_time}]").AppendLine();
            sb.Append(ip.HexPadLeft().HexDump()).Append($" //[Ip: {login_ip}]").AppendLine();
            sb.Append("00 00 00 00");
            return sb.ToString();
        }
    }
}
