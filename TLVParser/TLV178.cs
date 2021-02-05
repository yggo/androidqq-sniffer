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
    [Attributes.TLVParser(0x178)]
    public class TLV178 : IParser
    {
        public string Parse(IByteBuffer value)
        {
            StringBuilder sb = new StringBuilder();

            short country_code = value.ReadShort();
            short mobile_len = value.ReadShort();
            string mobile = value.ReadCharSequence(mobile_len, Encoding.UTF8).ToString();
            int smscode_status = value.ReadInt();
            short available_msg_cnt = value.ReadShort();
            short time_limit = value.ReadShort();

            sb.Append(country_code.HexPadLeft().HexDump()).Append(" //country_code").AppendLine();
            sb.Append(mobile_len.HexPadLeft().HexDump()).Append($" //mobile_len={mobile_len}").AppendLine();
            sb.Append(Encoding.UTF8.GetBytes(mobile).HexDump()).Append($" //[{mobile}]").AppendLine();
            sb.Append(smscode_status.HexPadLeft().HexDump()).Append(" //smscode_status").AppendLine();
            sb.Append(available_msg_cnt.HexPadLeft().HexDump()).Append(" //available_msg_cnt").AppendLine();
            sb.Append(time_limit.HexPadLeft().HexDump()).Append(" //time_limit").AppendLine();

            return sb.ToString();
        }
    }
}
