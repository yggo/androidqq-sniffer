using DotNetty.Buffers;
using System.Text;

namespace YgAndroidQQSniffer.TLVParser
{
    [Attributes.TLVParser(0x11D)]
    public class TLV11D : IParser
    {
        public string Parse(IByteBuffer value)
        {
            StringBuilder sb = new StringBuilder();

            int encrypt_appid = value.ReadInt();
            byte[] userSt_Key = value.ReadBytes(16).Array;
            short userStSigLen = value.ReadShort();
            byte[] userStSig = value.ReadRemainingBytes();

            sb.Append(encrypt_appid.HexPadLeft().HexDump()).Append($" //encrypt_appid(dec)={encrypt_appid}").AppendLine();
            sb.Append(userSt_Key.HexDump()).Append($" //userSt_Key").AppendLine();
            sb.Append(userStSigLen.HexPadLeft().HexDump()).Append($" //userStSigLen(dec)={userStSigLen}").AppendLine();
            sb.Append(userStSig.HexDump()).Append(" //userStSig").AppendLine();

            return sb.ToString();
        }
    }
}
