using DotNetty.Buffers;
using System.Text;

namespace YgAndroidQQSniffer.TLVParser
{
    [Attributes.TLVParser(0x104)]
    public class TLV104 : IParser
    {
        public string Parse(IByteBuffer value)
        {
            StringBuilder sb = new StringBuilder();

            byte[] tlv104_buf = Util.ReadRemainingBytes(value);

            sb.Append(tlv104_buf.HexDump()).Append($" //[Text: {Encoding.UTF8.GetString(tlv104_buf)}]").AppendLine();

            return sb.ToString();
        }
    }
}
