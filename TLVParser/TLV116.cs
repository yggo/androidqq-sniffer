/*
 *  Copyright 2021-2021 yggo Technologies and contributors.
 *
 *  此源代码的使用受 GNU AFFERO GENERAL PUBLIC LICENSE version 3 许可证的约束, 可以在以下链接找到该许可证.
 *  Use of this source code is governed by the GNU AGPLv3 license that can be found through the following link.
 *
 *  https://github.com/yggo/androidqq-sniffer/blob/main/LICENSE
 */

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
