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

namespace YgAndroidQQSniffer.TLVParser.TLV52D
{
    [Attributes.TLVParser(0x52D)]
    public class TLV52D : IParser
    {
        public string Parse(IByteBuffer value)
        {
            StringBuilder sb = new StringBuilder();
            sb.Append(value.Array.HexDump()).AppendLine();
            sb.Append(ParsePb(value)).AppendLine();
            return sb.ToString();
        }

        private string ParsePb(IByteBuffer bytes)
        {
            DeviceInfo deviceInfo = DeviceInfo.Parser.ParseFrom(bytes.Array);
            return string.Format("Bootloader: {0}\r\nProcVersion: {1}\r\nCodeName: {2}\r\nIncremental: {3}\r\nFingerprint: {4}\r\nBootId: {5}\r\nAndroidId: {6}\r\nBaseBand: {7}\r\nInnerVersion: {8}",
                deviceInfo.Bootloader.ToStringUtf8(), deviceInfo.ProcVersion.ToStringUtf8(), deviceInfo.CodeName.ToStringUtf8(),
                deviceInfo.Incremental.ToStringUtf8(), deviceInfo.Fingerprint.ToStringUtf8(), deviceInfo.BootID.ToStringUtf8(),
                deviceInfo.AndroidID.ToStringUtf8(), deviceInfo.BaseBand.ToStringUtf8(), deviceInfo.InnerVersion.ToStringUtf8());

        }
    }
}
