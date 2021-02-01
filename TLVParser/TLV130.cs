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
