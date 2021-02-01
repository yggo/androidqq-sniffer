using DotNetty.Buffers;
using System.Text;

namespace YgAndroidQQSniffer.TLVParser
{
    [Attributes.TLVParser(0x17E)]
    // devLockInfo
    public class TLV17E : IParser
    {
        public string Parse(IByteBuffer value)
        {
            StringBuilder sb = new StringBuilder();

            byte[] verifyReason = value.ReadRemainingBytes();

            sb.Append(verifyReason.HexDump()).Append($" //[verifyReason: {Encoding.UTF8.GetString(verifyReason)}]").AppendLine();

            return sb.ToString();
        }
    }
}
