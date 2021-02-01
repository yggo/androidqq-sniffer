using DotNetty.Buffers;
using System;
using System.Text;

namespace YgAndroidQQSniffer.TLVParser
{
    [Attributes.TLVParser(0x511)]
    public class TLV511 : IParser
    {
        public string Parse(IByteBuffer value)
        {
            StringBuilder sb = new StringBuilder();
            short domains = value.ReadShort();
            sb.Append(domains.HexPadLeft().HexDump());
            sb.Append($" //{domains}domains ").AppendLine();
            for (int i = 0; i < domains; i++)
            {
                value.ReadByte();
                short domain_len = value.ReadShort();
                string domain = value.ReadCharSequence(domain_len, Encoding.UTF8).ToString();
                sb.Append("01" + Environment.NewLine);
                sb.Append($"{domain_len.HexPadLeft().HexDump()} //len={domain_len}").AppendLine();
                sb.Append($"{Encoding.UTF8.GetBytes(domain).HexDump()} //[{domain}]").AppendLine();
            }
            return sb.ToString();
        }
    }
}
