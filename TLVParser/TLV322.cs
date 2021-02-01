using DotNetty.Buffers;
using System.Text;

namespace YgAndroidQQSniffer.TLVParser
{
    [Attributes.TLVParser(0x322)]
    public class TLV322 : IParser
    {
        public string Parse(IByteBuffer value)
        {
            StringBuilder sb = new StringBuilder();

            byte[] device_token = Util.ReadRemainingBytes(value);

            sb.Append(device_token.HexDump()).Append(" //device_token").AppendLine();
            return sb.ToString();
        }
    }
}
