using DotNetty.Buffers;
using System.Text;

namespace YgAndroidQQSniffer.TLVParser
{
    [Attributes.TLVParser(0x154)]
    public class TLV154 : IParser
    {
        public string Parse(IByteBuffer value)
        {
            StringBuilder sb = new StringBuilder();

            int sso_seq = value.ReadInt();
            sb.Append(sso_seq.HexPadLeft().HexDump()).Append($" //sso_seq {sso_seq}").AppendLine();

            return sb.ToString();
        }
    }
}
