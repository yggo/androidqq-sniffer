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
    [Attributes.TLVParser(0x11D)]
    public class TLV11D : IParser
    {
        public string Parse(IByteBuffer value)
        {
            StringBuilder sb = new StringBuilder();

            int encrypt_appid = value.ReadInt();
            byte[] userSt_Key = value.ReadBytes(16).Array;
            short userStSigLen = value.ReadShort();
            byte[] userStSig = value.ReadRemainingBytes();

            sb.Append(encrypt_appid.HexPadLeft().HexDump()).Append($" //encrypt_appid(dec)={encrypt_appid}").AppendLine();
            sb.Append(userSt_Key.HexDump()).Append($" //userSt_Key").AppendLine();
            sb.Append(userStSigLen.HexPadLeft().HexDump()).Append($" //userStSigLen(dec)={userStSigLen}").AppendLine();
            sb.Append(userStSig.HexDump()).Append(" //userStSig").AppendLine();

            return sb.ToString();
        }
    }
}
