using DotNetty.Buffers;
using System.Text;

namespace YgAndroidQQSniffer.TLVParser
{
    [Attributes.TLVParser(0x204)]
    // devLockInfo
    public class TLV204 : IParser
    {
        public string Parse(IByteBuffer value)
        {
            StringBuilder sb = new StringBuilder();

            byte[] otherDevLockVerifyUrl = value.ReadRemainingBytes();

            sb.Append(otherDevLockVerifyUrl.HexDump()).Append($" //[otherDevLockVerifyUrl: {Encoding.UTF8.GetString(otherDevLockVerifyUrl)}]").AppendLine();

            return sb.ToString();
        }
    }
}
