using DotNetty.Buffers;
using System.Text;

namespace YgAndroidQQSniffer.TLVParser
{
    [Attributes.TLVParser(0x10E)]
    public class TLV10E : IParser
    {
        public string Parse(IByteBuffer value)
        {
            StringBuilder sb = new StringBuilder();

            byte[] userStKey = Util.ReadRemainingBytes(value);

            sb.Append(userStKey.HexDump()).Append(" //userStKey").AppendLine();

            return sb.ToString();
        }
    }
}
