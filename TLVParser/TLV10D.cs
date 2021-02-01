using DotNetty.Buffers;
using System.Text;

namespace YgAndroidQQSniffer.TLVParser
{
    [Attributes.TLVParser(0x10D)]
    public class TLV10D : IParser
    {
        public string Parse(IByteBuffer value)
        {
            StringBuilder sb = new StringBuilder();

            byte[] tgtkey = Util.ReadRemainingBytes(value);

            sb.Append(tgtkey.HexDump()).Append(" //TGTKey").AppendLine();
            return sb.ToString();
        }
    }
}
