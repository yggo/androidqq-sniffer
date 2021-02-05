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
    [Attributes.TLVParser(0x11F)]
    public class TLV11F : IParser
    {
        public string Parse(IByteBuffer value)
        {
            StringBuilder sb = new StringBuilder();

            int chg_time = value.ReadInt();
            int tk_pri = value.ReadInt();
            byte[] remaining = Util.ReadRemainingBytes(value);

            sb.Append(chg_time.HexPadLeft().HexDump()).Append($" //chg_time {chg_time}").AppendLine();
            sb.Append(tk_pri.HexPadLeft().HexDump()).Append($" //tk_pri {tk_pri}").AppendLine();
            sb.Append(remaining.HexDump()).AppendLine();
            return sb.ToString();
        }
    }
}
