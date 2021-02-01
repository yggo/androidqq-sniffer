using DotNetty.Buffers;
using System.Text;

namespace YgAndroidQQSniffer.TLVParser
{
    [Attributes.TLVParser(0x194)]
    public class TLV194 : IParser
    {
        public string Parse(IByteBuffer value)
        {
            StringBuilder sb = new StringBuilder();
            sb.Append(Util.ReadRemainingBytes(value).HexDump())
                    .Append(" //md5(imsi)")
                    .AppendLine();
            return sb.ToString();
        }
    }
}
