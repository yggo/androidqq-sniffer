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
    [Attributes.TLVParser(0x202)]
    public class TLV202 : IParser
    {
        public string Parse(IByteBuffer value)
        {
            StringBuilder sb = new StringBuilder();

            short md5_bssid_len = value.ReadShort();
            byte[] md5_bssid = value.ReadBytes(md5_bssid_len).Array;
            short bssid_len = value.ReadShort();
            string bssid = value.ReadCharSequence(bssid_len, Encoding.UTF8).ToString();

            sb.Append(md5_bssid_len.HexPadLeft().HexDump()).AppendLine();
            sb.Append(md5_bssid.HexDump()).Append(" //md5(bssid)").AppendLine();
            sb.Append(bssid_len.HexPadLeft().HexDump()).AppendLine();
            sb.Append(Encoding.UTF8.GetBytes(bssid).HexDump()).Append($" //[bssid: {bssid}]").AppendLine();

            return sb.ToString();
        }
    }
}
