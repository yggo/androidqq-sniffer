using DotNetty.Buffers;
using System.Text;

namespace YgAndroidQQSniffer.TLVParser
{
    [Attributes.TLVParser(0x103)]
    public class TLV103 : IParser
    {

        public string Parse(IByteBuffer value)
        {
            StringBuilder sb = new StringBuilder();

            byte[] userStSig = Util.ReadRemainingBytes(value);

            sb.Append(userStSig.HexDump()).Append(" //userStSig").AppendLine();
            return sb.ToString();
        }
    }
}
