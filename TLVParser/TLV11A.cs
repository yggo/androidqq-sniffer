using DotNetty.Buffers;
using System.Text;

namespace YgAndroidQQSniffer.TLVParser
{
    [Attributes.TLVParser(0x11A)]
    public class TLV11A : IParser
    {
        public string Parse(IByteBuffer value)
        {
            StringBuilder sb = new StringBuilder();

            short face = value.ReadShort(); //face
            byte age = value.ReadByte();
            byte gender = value.ReadByte();
            byte nick_len = value.ReadByte();
            byte[] nick = Util.ReadRemainingBytes(value);

            sb.Append(face.HexPadLeft().HexDump()).AppendLine();
            sb.Append(age.HexPadLeft()).Append($" //age {age}").AppendLine();
            sb.Append(gender.HexPadLeft()).Append(" //gender").AppendLine();
            sb.Append(nick_len.HexPadLeft()).Append($" //nick_len={nick_len}").AppendLine();
            sb.Append(nick.HexDump()).Append($" //[{Encoding.UTF8.GetString(nick)}]").AppendLine();
            return sb.ToString();
        }
    }
}
