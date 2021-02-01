using DotNetty.Buffers;
using System.Text;

namespace YgAndroidQQSniffer.TLVParser
{
    [Attributes.TLVParser(0x10A)]
    public class TLV10A : IParser
    {
        public string Parse(IByteBuffer value)
        {
            StringBuilder sb = new StringBuilder();

            byte[] tgt = Util.ReadRemainingBytes(value);

            sb.Append(tgt.HexDump()).Append(" //TGT").AppendLine();
            return sb.ToString();
        }
    }
}
