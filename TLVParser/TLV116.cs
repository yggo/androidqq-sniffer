using DotNetty.Buffers;
using System.Text;

namespace YgAndroidQQSniffer.TLVParser
{
    [Attributes.TLVParser(0x116)]
    public class TLV116 : IParser
    {
        public string Parse(IByteBuffer value)
        {
            StringBuilder sb = new StringBuilder();

            byte ver = value.ReadByte();
            int miscBitmap = value.ReadInt();
            int subSigMap = value.ReadInt();
            byte subAppidListLength = value.ReadByte();

            sb.Append(ver.HexPadLeft()).Append(" //ver").AppendLine();
            sb.Append(miscBitmap.HexPadLeft().HexDump()).Append($" //miscBitmap(dec)={miscBitmap}").AppendLine();
            sb.Append(subSigMap.HexPadLeft().HexDump()).Append($" //subSigMap(dec)={subSigMap}").AppendLine();
            sb.Append(subAppidListLength.HexPadLeft()).Append($" //subAppidListLength={subAppidListLength}").AppendLine();
            for (int i = 0; i < subAppidListLength; i++)
            {
                int appid = value.ReadInt();
                sb.Append(appid.HexPadLeft().HexDump()).Append($" //subAppid(dec)={appid}").AppendLine();
            }

            return sb.ToString();
        }
    }
}
