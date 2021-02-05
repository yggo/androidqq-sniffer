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
    [Attributes.TLVParser(0x177)]
    public class TLV177 : IParser
    {
        public string Parse(IByteBuffer value)
        {
            StringBuilder sb = new StringBuilder();

            byte unknownConst1 = value.ReadByte();
            int releaseTimestamp = value.ReadInt();
            short sdkVersionLen = value.ReadShort();
            string sdkVersion = value.ReadCharSequence(sdkVersionLen, Encoding.UTF8).ToString();

            sb.Append(unknownConst1.HexPadLeft().HexDump()).AppendLine();
            sb.Append(releaseTimestamp.HexPadLeft().HexDump()).Append($" //[releaseTimestamp: {Util.UnixTimeStampToDateTime(releaseTimestamp)}]").AppendLine();
            sb.Append(sdkVersionLen.HexPadLeft().HexDump()).AppendLine();
            sb.Append(Encoding.UTF8.GetBytes(sdkVersion).HexDump()).Append($" //[sdkVersion: {sdkVersion}]").AppendLine();

            return sb.ToString();
        }
    }
}
