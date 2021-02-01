using DotNetty.Buffers;
using System.Text;

namespace YgAndroidQQSniffer.TLVParser
{
    [Attributes.TLVParser(0x114)]
    public class TLV114 : IParser
    {
        public string Parse(IByteBuffer value)
        {
            StringBuilder sb = new StringBuilder();

            byte[] userStKey = Util.ReadRemainingBytes(value);

            sb.Append(userStKey.HexDump()).Append(" //userSt").AppendLine();

            return sb.ToString();
        }
    }
}
