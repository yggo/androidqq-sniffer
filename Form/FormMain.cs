﻿/*
 *  Copyright 2021-2021 yggo Technologies and contributors.
 *
 *  此源代码的使用受 GNU AFFERO GENERAL PUBLIC LICENSE version 3 许可证的约束, 可以在以下链接找到该许可证.
 *  Use of this source code is governed by the GNU AGPLv3 license that can be found through the following link.
 *
 *  https://github.com/yggo/androidqq-sniffer/blob/main/LICENSE
 */

using DotNetty.Buffers;
using NLog;
using SharpPcap;
using SharpPcap.LibPcap;
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
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

        private static Logger Logger { get; } = LogManager.GetCurrentClassLogger();

        private RealTimePacketsAnalyzer RealTimePacketsAnalyzer { get; } = new RealTimePacketsAnalyzer();

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
              ?.SetValue(lv_packet_log, true, null);
            lv_analysis_log
                .GetType()
                .GetProperty("DoubleBuffered", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)
                ?.SetValue(lv_packet_log, true, null);
        }

        private void RegCustomEvents()
        {
            static bool IsCustomEventAttrbute(Attribute[] o)
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
            if (Device != null && Device.Started)
            {
                Logger.Info(Device.Statistics.ToString());
                Device.StopCapture();
                Device.Close();
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
            r_txt_log.Select(old_start + old_length, 0);
        }
        public void Log(string text, params object[] args)
        {
            Log(string.Format(text, args));
        }

        #endregion

        /// <summary>
        /// 当前下拉框选中的网卡
        /// </summary>
        public ICaptureDevice Device { get; set; }
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
            List<PacketAnalyzer> analysisPackets = new List<PacketAnalyzer>();
            ListViewItem[] currentItems = new ListViewItem[lv_packet_log.Items.Count];
            lv_packet_log.Items.CopyTo(currentItems, 0);
            lv_analysis_log.Items.Clear();

            foreach (ListViewItem item in currentItems)
            {
                string captureTime = item.SubItems[4].Text;
                byte[] payload = item.SubItems[6].Text.DecodeHex();
                IByteBuffer buffer = Unpooled.WrappedBuffer(payload);
                if (RealTimePacketsAnalyzer.IsAndroidQQProtocol(buffer))
                {
                    int pkgLen = buffer.GetInt(buffer.ReaderIndex);
                    byte[] pkgPayload = new byte[pkgLen];
                    if (buffer.ReadableBytes >= pkgPayload.Length)
                    {
                        buffer.ReadBytes(pkgPayload, 0, pkgPayload.Length);
                        analysisPackets.Add(new PacketAnalyzer()
                        {
                            Payload = payload,
                            CaptureTime = captureTime,
                            HexPayload = item.SubItems[6].Text
                        });
                    }
                }
            }

            foreach (PacketAnalyzer item in analysisPackets)
            {
                try
                {
                    item.Deserialize();
                    Logger.Info(item.ToString());
                    var lvi = new ListViewItem
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
                        Tag = item,
                        ForeColor = item.Orientation == "Send" ? Color.Red : Color.Blue
                    };
                    ThreadSafeUpdate(() => lv_analysis_log.Items.Add(lvi));
                }
                catch (Exception ex)
                {
                    Logger.Error(ex, ex.Message + " hex: " + item.HexPayload);
                }
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
            Device.Open(DeviceMode.Normal, 1000);
            Device.Filter = "tcp port 8080 or tcp port 14000 or tcp port 443";
            Device.OnPacketArrival += Device_OnPacketArrival;
            Device.StartCapture();
            RealTimePacketsAnalyzer.StartAnalysisThread();
        }

        private void Button_stop_capture_Click(object sender, EventArgs e)
        {
            if (Device != null)
            {
                try
                {
                    Device.OnPacketArrival -= Device_OnPacketArrival;
                    Device.StopCapture();
                    Device.Close();
                }
                catch (Exception)
                {
                    // ignored
                }
            }
        }

        private void Button_clear_packet_log_Click(object sender, EventArgs e)
        {
            lv_packet_log.Items.Clear();
        }

        private void Device_OnPacketArrival(object sender, CaptureEventArgs e)
        {
            var captureTime = e.Packet.Timeval.Date.ToLocalTime();
            var packet = PacketDotNet.Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
            var tcpPacket = packet.Extract<PacketDotNet.TcpPacket>();


            if (tcpPacket != null)
            {
                RealTimePacketsAnalyzer.ProcessPackets(tcpPacket);
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
