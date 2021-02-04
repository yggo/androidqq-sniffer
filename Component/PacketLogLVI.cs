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
