using DotNetty.Buffers;
using System.Text;

namespace YgAndroidQQSniffer.TLVParser
{
    [Attributes.TLVParser(0x109)]
    public class TLV109 : IParser
    {
        public string Parse(IByteBuffer value)
        {
            StringBuilder sb = new StringBuilder();
            sb.Append(Util.ReadRemainingBytes(value).HexDump())
                .Append(" //md5(androidID)")
                .AppendLine();
            return sb.ToString();
        }
    }
}
