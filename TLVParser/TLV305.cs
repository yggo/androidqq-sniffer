using DotNetty.Buffers;
using System;
using System.Text;

namespace YgAndroidQQSniffer.TLVParser
{
    [Attributes.TLVParser(0x305)]
    public class TLV305 : IParser
    {
        public string Parse(IByteBuffer value)
        {
            StringBuilder sb = new StringBuilder();
            sb.Append(Util.ReadRemainingBytes(value).HexDump())
                .Append(" //d2key or session key 登录成功后续的操作需要用这个key作为tea加密的秘钥")
                .AppendLine();
            return sb.ToString();
        }
    }
}
