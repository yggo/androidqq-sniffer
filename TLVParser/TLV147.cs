using DotNetty.Buffers;
using System.Text;

namespace YgAndroidQQSniffer.TLVParser
{
    [Attributes.TLVParser(0x147)]
    public class TLV147 : IParser
    {
        public string Parse(IByteBuffer value)
        {
            StringBuilder sb = new StringBuilder();

            int limit_len = value.ReadInt();
            short apkVersionNameLen = value.ReadShort();
            string apkVersionName = value.ReadCharSequence(apkVersionNameLen, Encoding.UTF8).ToString();
            short apkSignatureMd5Len = value.ReadShort();
            byte[] apkSignatureMd5 = value.ReadBytes(apkSignatureMd5Len).Array;

            sb.Append(limit_len.HexPadLeft().HexDump()).AppendLine();
            sb.Append(apkVersionNameLen.HexPadLeft().HexDump()).AppendLine();
            sb.Append(Encoding.UTF8.GetBytes(apkVersionName).HexDump()).Append($" //[apkVersionName: {apkVersionName}]").AppendLine();
            sb.Append(apkSignatureMd5Len.HexPadLeft().HexDump()).AppendLine();
            sb.Append(apkSignatureMd5.HexDump()).Append(" //apkSignatureMd5").AppendLine();

            return sb.ToString();
        }
    }
}
