using DotNetty.Buffers;
using System.Text;

namespace YgAndroidQQSniffer.TLVParser
{
    [Attributes.TLVParser(0x11F)]
    public class TLV11F : IParser
    {
        public string Parse(IByteBuffer value)
        {
            StringBuilder sb = new StringBuilder();

            int chg_time = value.ReadInt();
            int tk_pri = value.ReadInt();
            byte[] remaining = Util.ReadRemainingBytes(value);

            sb.Append(chg_time.HexPadLeft().HexDump()).Append($" //chg_time {chg_time}").AppendLine();
            sb.Append(tk_pri.HexPadLeft().HexDump()).Append($" //tk_pri {tk_pri}").AppendLine();
            sb.Append(remaining.HexDump()).AppendLine();
            return sb.ToString();
        }
    }
}
