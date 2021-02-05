/*
 *  Copyright 2021-2021 yggo Technologies and contributors.
 *
 *  此源代码的使用受 GNU AFFERO GENERAL PUBLIC LICENSE version 3 许可证的约束, 可以在以下链接找到该许可证.
 *  Use of this source code is governed by the GNU AGPLv3 license that can be found through the following link.
 *
 *  https://github.com/yggo/androidqq-sniffer/blob/main/LICENSE
 */

using System.Windows.Forms;

namespace YgAndroidQQSniffer.Component
{
    public class PacketLogLVI
    {
        public string Index { get; set; }
        public string Orientation { get; set; }
        public string SrcIp { get; set; }
        public string DstIp { get; set; }
        public string CaptureTime { get; set; }
        public string PayloadLen { get; set; }
        public string PayloadData { get; set; }
        public object Tag { get; set; }

        public ListViewItem BuildLVI()
        {
            return new ListViewItem()
            {
                Text = Index,
                SubItems =
                {
                    Orientation,
                    SrcIp,
                    DstIp,
                    CaptureTime,
                    PayloadLen,
                    PayloadData
                },
                Tag = Tag
            };
        }
    }
}
