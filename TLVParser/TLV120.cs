using DotNetty.Buffers;
using System;
using System.Text;

namespace YgAndroidQQSniffer.TLVParser
{
    [Attributes.TLVParser(0x120)]
    public class TLV120 : IParser
    {
        public string Parse(IByteBuffer value)
        {
            StringBuilder sb = new StringBuilder();
            byte[] skey = Util.ReadRemainingBytes(value);
            sb.Append(skey.HexDump()).Append($" //[skey: {Encoding.UTF8.GetString(skey)}]").AppendLine();
            return sb.ToString();
        }
    }
}
