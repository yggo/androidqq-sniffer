using DotNetty.Buffers;
using System.Text;

namespace YgAndroidQQSniffer.TLVParser
{
    [Attributes.TLVParser(0x143)]
    public class TLV143 : IParser
    {
        public string Parse(IByteBuffer value)
        {
            StringBuilder sb = new StringBuilder();

            byte[] D2 = Util.ReadRemainingBytes(value);

            sb.Append(D2.HexDump()).Append(" //D2").AppendLine();
            return sb.ToString();
        }
    }
}
