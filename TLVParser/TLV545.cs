using DotNetty.Buffers;
using System.Text;

namespace YgAndroidQQSniffer.TLVParser
{
    [Attributes.TLVParser(0x545)]
    public class TLV545 : IParser
    {
        public string Parse(IByteBuffer value)
        {
            StringBuilder sb = new StringBuilder();
            sb.Append(Util.ReadRemainingBytes(value).HexDump())
                .Append(" //md5(imei or qimei)")
                .AppendLine();
            return sb.ToString();
        }
    }
}
