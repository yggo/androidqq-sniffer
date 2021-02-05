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
    [Attributes.TLVParser(0x11A)]
    public class TLV11A : IParser
    {
        public string Parse(IByteBuffer value)
        {
            StringBuilder sb = new StringBuilder();

            short face = value.ReadShort(); //face
            byte age = value.ReadByte();
            byte gender = value.ReadByte();
            byte nick_len = value.ReadByte();
            byte[] nick = Util.ReadRemainingBytes(value);

            sb.Append(face.HexPadLeft().HexDump()).AppendLine();
            sb.Append(age.HexPadLeft()).Append($" //age {age}").AppendLine();
            sb.Append(gender.HexPadLeft()).Append(" //gender").AppendLine();
            sb.Append(nick_len.HexPadLeft()).Append($" //nick_len={nick_len}").AppendLine();
            sb.Append(nick.HexDump()).Append($" //[{Encoding.UTF8.GetString(nick)}]").AppendLine();
            return sb.ToString();
        }
    }
}
