using DotNetty.Buffers;
using System;
using System.Text;

namespace YgAndroidQQSniffer.TLVParser
{
    [Attributes.TLVParser(0x16D)]
    public class TLV16D : IParser
    {
        public string Parse(IByteBuffer value)
        {
            StringBuilder sb = new StringBuilder();
            byte[] superkey = Util.ReadRemainingBytes(value);
            sb.Append(superkey.HexDump()).AppendLine()
                .Append($"//[superkey: {Encoding.UTF8.GetString(superkey)}]")
                .AppendLine();
            return sb.ToString();
        }
    }
}
