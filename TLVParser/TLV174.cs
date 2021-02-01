using DotNetty.Buffers;
using System.Text;

namespace YgAndroidQQSniffer.TLVParser
{
    [Attributes.TLVParser(0x174)]
    public class TLV174 : IParser
    {
        public string Parse(IByteBuffer value)
        {
            StringBuilder sb = new StringBuilder();

            byte[] tlv174_buf = Util.ReadRemainingBytes(value);

            sb.Append(tlv174_buf.HexDump()).Append($" //[Text: {Encoding.UTF8.GetString(tlv174_buf)}]").AppendLine();

            return sb.ToString();
        }
    }
}
