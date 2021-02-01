using DotNetty.Buffers;
using System.Text;

namespace YgAndroidQQSniffer.TLVParser
{
    [Attributes.TLVParser(0x192)]
    public class TLV192 : IParser
    {
        public string Parse(IByteBuffer value)
        {
            StringBuilder sb = new StringBuilder();

            byte[] tlv192_buf = Util.ReadRemainingBytes(value);

            sb.Append(tlv192_buf.HexDump()).Append($" //[Text: {Encoding.UTF8.GetString(tlv192_buf)}]").AppendLine();

            return sb.ToString();
        }
    }
}
