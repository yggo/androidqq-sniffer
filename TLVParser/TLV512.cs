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
    [Attributes.TLVParser(0x512)]
    public class TLV512 : IParser
    {
        public string Parse(IByteBuffer value)
        {
            StringBuilder sb = new StringBuilder();
            short domains = value.ReadShort();
            sb.Append(domains.HexPadLeft().HexDump()).Append($" //{domains}domains ").AppendLine();
            for (int i = 0; i < domains; i++)
            {
                short domain_len = value.ReadShort();
                string domain = value.ReadCharSequence(domain_len, Encoding.UTF8).ToString();
                short pskey_len = value.ReadShort();
                string pskey = value.ReadCharSequence(pskey_len, Encoding.UTF8).ToString();
                value.ReadShort();//separator

                sb.Append(domain_len.HexPadLeft().HexDump()).Append($" //len={domain_len}").AppendLine();
                sb.Append(Encoding.UTF8.GetBytes(domain).HexDump()).Append($" //[{domain}]").AppendLine();

                sb.Append(pskey_len.HexPadLeft().HexDump()).Append($" //len={pskey_len}").AppendLine();
                sb.Append(Encoding.UTF8.GetBytes(pskey).HexDump()).AppendLine().Append($"//[pskey: {pskey}]").AppendLine();
            }
            return sb.ToString();
        }
    }
}
