using App.Metrics.Concurrency;
using DotNetty.Buffers;
using DotNetty.Common.Utilities;
using NLog;
using SharpPcap;
using SharpPcap.LibPcap;
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using YgAndroidQQSniffer.Component;
using YgAndroidQQSniffer.PbParser;
using YgAndroidQQSniffer.TLVParser;

namespace YgAndroidQQSniffer
{
    public partial class FormMain : Form
    {
        public static FormMain Form { get; private set; }

        public static Logger Logger { get; set; } = LogManager.GetCurrentClassLogger();

        public FormMain()
        {
            InitializeComponent();
        }

        #region FormMain Common
        #region FormMain Load
        private void FormMain_Load(object sender, EventArgs e)
        {
            Form = this;
            OptimizeListView();
            RegCustomEvents();
            TLVFormatter.RegTLVParsers();
        }

        private void OptimizeListView()
        {
            lv_packet_log
              .GetType()
              .GetProperty("DoubleBuffered", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)
              .SetValue(lv_packet_log, true, null);
            lv_analysis_log
                .GetType()
                .GetProperty("DoubleBuffered", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)
                .SetValue(lv_packet_log, true, null);
        }

        private void RegCustomEvents()
        {
            bool IsCustomEventAttrbute(Attribute[] o)
            {
                foreach (Attribute a in o)
                {
                    if (a is Attributes.CustomEvent)
                        return true;
                }
                return false;
            }

            Type[] types = typeof(Attributes.CustomEvent).GetExportedTypes().Where(o => IsCustomEventAttrbute(Attribute.GetCustomAttributes(o, false))).ToArray();
            foreach (Type type in types)
            {
                if (type.GetInterface(nameof(ICustomControlEvents)) != null)
                {
                    var clazz = (ICustomControlEvents)type.Assembly.CreateInstance(type.FullName);
                    clazz.Register();
                }
                else
                {
                    Logger.Warn("【警告】标注了{0}属性的{1}类务必实现{2}接口, 否则不会注册控件事件",
                        nameof(Attributes.CustomEvent), type.FullName, nameof(ICustomControlEvents));
                }
            }
        }

        #endregion
        private void FormMain_FormClosing(object sender, FormClosingEventArgs e)
        {
            if (Device != null)
            {
                if (Device.Started)
                {
                    Logger.Info(Device.Statistics.ToString());
                    Device.StopCapture();
                    Device.Close();
                }
            }
        }

        public void ThreadSafeUpdate(Action action)
        {
            Invoke(action);
        }

        /// <summary>
        /// 将字符串打印到富文本编辑框中
        /// </summary>
        /// <param name="text"></param>
        public void Log(string text)
        {
            string old_text = Clipboard.GetText();
            int old_start = r_txt_log.SelectionStart;
            int old_length = r_txt_log.SelectionLength;
            r_txt_log.Select(old_start + old_length, 0);
            Clipboard.SetText(text);
            r_txt_log.Paste();
            Clipboard.SetText(old_text);
        }
        public void Log(string text, params object[] args)
        {
            Log(string.Format(text, args));
        }

        #endregion

        /// <summary>
        /// 当前下拉框选中的网卡
        /// </summary>
        private ICaptureDevice Device { get; set; }
        /// <summary>
        /// 当前下拉框选中的网卡的IP
        /// </summary>
        private string SelectedDeviceIpAddr { get; set; }

        /// <summary>
        /// 读取网卡信息
        /// </summary>
        private void LoadDevice()
        {
            new Thread(() =>
            {
                try
                {
                    ThreadSafeUpdate(() => cbx_device.Enabled = false);
                    ThreadSafeUpdate(() => btn_load_device.Enabled = false);
                    ThreadSafeUpdate(() => btn_load_device.Text = "读取中");

                    if (Device != null)
                    {
                        CaptureDeviceList.Instance.Refresh();
                        return;
                    }
                    ThreadSafeUpdate(() => cbx_device.Items.Clear());
                    foreach (PcapDevice device in CaptureDeviceList.Instance)
                    {
                        ThreadSafeUpdate(() => cbx_device.Items.Add(new DeviceItem() { Device = device }));
                    }

                }
                catch (Exception ex)
                {
                    Toast.Failed(ex.Message);
                }
                finally
                {
                    ThreadSafeUpdate(() =>
                    {
                        btn_load_device.Enabled = true;
                        btn_load_device.Text = "读取网卡";
                        cbx_device.Enabled = true;
                        if (cbx_device.Items.Count > 0)
                        {
                            cbx_device.SelectedIndex = 0;
                        }
                    });
                }
            }).Start();
        }

        private void Cbx_device_SelectedIndexChanged(object sender, EventArgs e)
        {
            Device = CaptureDeviceList.Instance[cbx_device.SelectedIndex];
            SelectedDeviceIpAddr = ((DeviceItem)cbx_device.SelectedItem).IpAddr;
        }

        private void Btn_Auto_Analysis_Click(object sender, EventArgs e)
        {
            StringBuilder sb_all = new StringBuilder();
            foreach (ListViewItem item in lv_packet_log.Items)
            {
                if (item.Tag is PacketAnalyzer analysisPacket)
                {
                    sb_all.Append(analysisPacket.HexPayload);
                }
            }
            if (string.IsNullOrEmpty(sb_all.ToString())) return;
            List<byte[]> bytes = new List<byte[]>();
            List<PacketAnalyzer> analysisPackets = new List<PacketAnalyzer>();

            var buf = Unpooled.WrappedBuffer(HexUtil.DecodeHex(sb_all.ToString()));

            try
            {
                try
                {
                    while (buf.IsReadable())
                    {
                        byte[] tag = new byte[5];
                        buf.GetBytes(buf.ReaderIndex + 4, tag, 0, 5);
                        switch (tag.HexDump())
                        {
                            case "00 00 00 0A 00":
                            case "00 00 00 0A 01":
                            case "00 00 00 0A 02":
                            case "00 00 00 0B 00":
                            case "00 00 00 0B 01":
                            case "00 00 00 0B 02":
                                int pkg_len = buf.GetInt(buf.ReaderIndex);
                                byte[] pkg_payload = new byte[pkg_len];
                                if (buf.ReadableBytes >= pkg_payload.Length)
                                {
                                    buf.ReadBytes(pkg_payload, 0, pkg_payload.Length);
                                    bytes.Add(pkg_payload);
                                }
                                break;
                            default:
                                buf.ReadBytes(9);
                                break;
                        }
                    }
                }
                catch (Exception ex)
                {
                    Logger.Error(ex, ex.Message);
                }
                foreach (byte[] payload in bytes)
                {
                    //TODO 优化这里的捕获时间
                    string capture_time = string.Empty;
                    /*foreach (ListViewItem item in listView_packet_log.Items)
                    {
                        if (payload.HexDump().Contains(item.SubItems[6].Text))
                        {
                            capture_time = item.SubItems[4].Text;
                            break;
                        }
                    }*/
                    analysisPackets.Add(new PacketAnalyzer()
                    {
                        Payload = payload,
                        CaptureTime = capture_time
                        //read capture time 
                    });
                }
                lv_analysis_log.Items.Clear();
                foreach (var item in analysisPackets)
                {
                    try
                    {
                        item.Deserialize();
                        Logger.Info(item.ToString());
                        var lvi = new ListViewItem()
                        {
                            Text = item.Orientation,
                            SubItems =
                            {
                                item.ServiceCmd,
                                item.SSOReq,
                                item.Payload.Length.ToString(),
                                item.CaptureTime,
                                item.HexPayload
                            },
                            Tag = new PacketAnalyzer { HexPayload = item.HexPayload }
                        };
                        if (item.Orientation == "Send")
                        {
                            lvi.ForeColor = Color.Red;
                        }
                        else
                        {
                            lvi.ForeColor = Color.Blue;
                        }
                        ThreadSafeUpdate(() => lv_analysis_log.Items.Add(lvi));
                    }
                    catch (Exception ex)
                    {
                        Logger.Error(ex, ex.Message + " hex: " + item.Payload.HexDump());
                    }
                }
            }
            finally
            {
                ReferenceCountUtil.Release(buf);
            }
        }

        private void Button_load_device_Click(object sender, EventArgs e)
        {
            LoadDevice();
        }

        private void Button_start_capture_Click(object sender, EventArgs e)
        {
            if (Device == null || Device.Started) return;
            lv_packet_log.Items.Clear();
            Common.Index = new AtomicInteger();
            Device.Open(DeviceMode.Normal, 1000);
            Device.Filter = "tcp port 8080 or tcp port 14000 or tcp port 443";
            Device.OnPacketArrival += new PacketArrivalEventHandler(Device_OnPacketArrival);
            Device.StartCapture();
        }

        private void Button_stop_capture_Click(object sender, EventArgs e)
        {
            if (Device != null)
            {
                try
                {
                    _dstIp = null;
                    Device.OnPacketArrival -= new PacketArrivalEventHandler(Device_OnPacketArrival);
                    Device.StopCapture();
                    Device.Close();
                }
                catch (Exception) { }
            }
        }

        private void Button_clear_packet_log_Click(object sender, EventArgs e)
        {
            lv_packet_log.Items.Clear();
            Common.Index = new AtomicInteger(0);
        }
        private string _dstIp { get; set; }
        private void Device_OnPacketArrival(object sender, CaptureEventArgs e)
        {
            var time = e.Packet.Timeval.Date.ToLocalTime();
            var len = e.Packet.Data.Length;
            var packet = PacketDotNet.Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
            var tcpPacket = packet.Extract<PacketDotNet.TcpPacket>();

            if (tcpPacket != null)
            {
                var ipPacket = (PacketDotNet.IPPacket)tcpPacket.ParentPacket;
                IPAddress srcIp = ipPacket.SourceAddress;
                IPAddress dstIp = ipPacket.DestinationAddress;
                int srcPort = tcpPacket.SourcePort;
                int dstPort = tcpPacket.DestinationPort;
                string data = tcpPacket.PayloadData.HexDump();
                int payload_len = tcpPacket.PayloadData.Length;

                if (payload_len == 0 || data == "00") return;

                string orientation = string.Empty;
                if (srcIp.ToString() == SelectedDeviceIpAddr)
                {
                    orientation = "Send";
                }
                else
                {
                    orientation = "Recv";
                }
                ListViewItem lv = null;
                if (_dstIp == null)
                {
                    //首次捕获
                    var buf = Unpooled.WrappedBuffer(HexUtil.DecodeHex(data));
                    try
                    {
                        if (buf.ReadableBytes < 9) return;
                        byte[] tag = new byte[5];
                        buf.GetBytes(buf.ReaderIndex + 4, tag, 0, 5);
                        switch (tag.HexDump())
                        {
                            case "00 00 00 0A 00":
                            case "00 00 00 0A 01":
                            case "00 00 00 0A 02":
                            case "00 00 00 0B 00":
                            case "00 00 00 0B 01":
                            case "00 00 00 0B 02":
                                _dstIp = dstIp.ToString();
                                lv = new ListViewItem()
                                {
                                    Text = Common.Index.Increment(1).ToString(),
                                    SubItems =
                                    {
                                        orientation,
                                        $"{srcIp}:{srcPort}",
                                        $"{dstIp}:{dstPort}",
                                        time.ToString(),
                                        payload_len.ToString(),
                                        data,
                                        tcpPacket.SequenceNumber.ToString(),
                                        tcpPacket.AcknowledgmentNumber.ToString()
                                    },
                                    Tag = new PacketAnalyzer() { HexPayload = data }
                                };
                                break;
                            default:
                                break;
                        }
                    }
                    finally
                    {
                        ReferenceCountUtil.Release(buf);
                    }
                }
                else
                {
                    if (srcIp.ToString() == _dstIp || dstIp.ToString() == _dstIp)
                    {
                        lv = new ListViewItem()
                        {
                            Text = Common.Index.Increment(1).ToString(),
                            SubItems =
                        {
                            orientation,
                            $"{srcIp}:{srcPort}",
                            $"{dstIp}:{dstPort}",
                            time.ToString(),
                            payload_len.ToString(),
                            data,
                            tcpPacket.SequenceNumber.ToString(),
                            tcpPacket.AcknowledgmentNumber.ToString()
                        },
                            Tag = new PacketAnalyzer() { HexPayload = data }
                        };
                    }
                }

                ThreadSafeUpdate(() =>
                {
                    if (lv != null)
                    {
                        if (orientation == "Send")
                        {
                            lv.ForeColor = Color.Red;
                        }
                        else
                        {
                            lv.ForeColor = Color.Blue;
                        }
                        lv_packet_log.Items.Add(lv);
                    }
                });
            }
        }

        private void 追踪流ToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (lv_packet_log.SelectedItems.Count != 1) return;
            ListViewItem selected_item = lv_packet_log.SelectedItems[0];
            string selected_item_seq = selected_item.SubItems[7].Text;
            string selected_item_ack = selected_item.SubItems[8].Text;

            Console.WriteLine("selected: " + selected_item_seq + " " + selected_item_ack);
            var pkgs = lv_packet_log.Items;
            List<string> sends = new List<string>();
            List<string> recvs = new List<string>();
            StringBuilder sb_send = new StringBuilder();
            StringBuilder sb_recv = new StringBuilder();
            StringBuilder sb_packets = new StringBuilder();
            foreach (ListViewItem pkg in pkgs)
            {
                string index = pkg.Text;
                string pkg_seq = pkg.SubItems[7].Text;
                string pkg_ack = pkg.SubItems[8].Text;
                string data = string.Empty;
                if (pkg.Tag is PacketAnalyzer analysisPacket)
                {
                    data = analysisPacket.HexPayload;
                }
                if (pkg_seq == selected_item_ack)
                {
                    Console.WriteLine($"recv: {data}");
                }
                else if (pkg_ack == selected_item_seq)
                {
                    Console.WriteLine($"send: {data}");
                }
                // 如果这个recv的包很大，比如收到了3个包，当我们检测到第一个包为recv包后
                // 需要再查找它余下的包
                selected_item_seq = pkg_seq;
                selected_item_ack = pkg_ack;
                sb_packets.Append(data);
            }
            List<byte[]> bytes = new List<byte[]>();
            List<PacketAnalyzer> analysisPackets = new List<PacketAnalyzer>();
            var buf = Unpooled.WrappedBuffer(HexUtil.DecodeHex(sb_packets.ToString()));

            try
            {
                while (buf.IsReadable())
                {
                    int pkg_len = buf.ReadInt();
                    byte[] tag = new byte[5];
                    buf.GetBytes(buf.ReaderIndex, tag, 0, 5);
                    switch (tag.HexDump())
                    {
                        case "00 00 00 0A 00":
                        case "00 00 00 0A 01":
                        case "00 00 00 0A 02":
                        case "00 00 00 0B 00":
                        case "00 00 00 0B 01":
                        case "00 00 00 0B 02":
                            byte[] pkg_payload = new byte[pkg_len - 4];
                            if (buf.ReadableBytes >= pkg_payload.Length)
                            {
                                buf.ReadBytes(pkg_payload, 0, pkg_payload.Length);
                                bytes.Add(pkg_payload);
                            }
                            break;
                        default:

                            break;
                    }
                    /*byte[] pkg_payload = new byte[pkg_len - 4];
                    if (buf.ReadableBytes >= pkg_payload.Length)
                    {
                        buf.ReadBytes(pkg_payload, 0, pkg_payload.Length);
                        bytes.Add(pkg_payload);
                    }
                    else
                    {
                        Logger.Warn("剩余字节大小不足，请检查追踪的流是否有问题！");
                        Console.WriteLine(Util.ReadRemainingBytes(buf).HexDump());

                        break;
                    }*/
                }
            }
            catch (Exception ex)
            {
                Logger.Error(ex, ex.Message);
            }
            foreach (byte[] payload in bytes)
            {
                analysisPackets.Add(new PacketAnalyzer()
                {
                    Payload = payload
                });
            }
            lv_analysis_log.Items.Clear();
            foreach (var item in analysisPackets)
            {
                try
                {
                    item.Deserialize();
                    Logger.Info(item.ToString());
                    var lvi = new ListViewItem()
                    {
                        Text = item.Orientation,
                        SubItems =
                        {
                            item.ServiceCmd,
                            item.SSOReq,
                            (item.Payload.Length + 4).ToString(),
                            item.HexPayload
                        }
                    };
                    if (item.Orientation == "Send")
                    {
                        lvi.BackColor = Color.FromArgb(251, 237, 237);
                    }
                    else
                    {
                        lvi.BackColor = Color.FromArgb(237, 237, 251);
                    }
                    ThreadSafeUpdate(() => lv_analysis_log.Items.Add(lvi));
                }
                catch (Exception ex)
                {
                    Logger.Error(ex, ex.Message + " hex: " + item.Payload.HexDump());
                }
            }
        }

        private void JceStructToolStripMenuItem_Click(object sender, EventArgs e)
        {
            throw new NotImplementedException();
        }

        private void ProtobufToolStripMenuItem_Click(object sender, EventArgs e)
        {
            string selected_text = r_txt_log.SelectedText.ClearSpecialSymbols();
            if (string.IsNullOrEmpty(selected_text)) return;
            string ret = new PbFormatter().Parse(Unpooled.WrappedBuffer(HexUtil.DecodeHex(selected_text)));
            Log($"\n[\n{ret}\n]\n");
        }

    }
}
