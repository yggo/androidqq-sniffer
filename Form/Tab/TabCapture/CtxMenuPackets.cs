﻿/*
 *  Copyright 2021-2021 yggo Technologies and contributors.
 *
 *  此源代码的使用受 GNU AFFERO GENERAL PUBLIC LICENSE version 3 许可证的约束, 可以在以下链接找到该许可证.
 *  Use of this source code is governed by the GNU AGPLv3 license that can be found through the following link.
 *
 *  https://github.com/yggo/androidqq-sniffer/blob/main/LICENSE
 */

using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using YgAndroidQQSniffer.Component;
using YgAndroidQQSniffer.Extension;

namespace YgAndroidQQSniffer.Tab.TabCapture
{
    [Attributes.CustomEvent(nameof(CtxMenuPackets))]
    public class CtxMenuPackets : ICustomControlEvents
    {
        private static FormMain Frm => FormMain.Form;

        public void Register()
        {
            Frm.copy_choose_payload.Click += CopyChoosePayload_Click;
            Frm.copy_whole_payload.Click += CopyWholePayload_Click;
            Frm.read_capture_packets_logs.Click += ReadCapturePacketsLogs_Click;
            Frm.save_capture_packets_logs.Click += SaveCapturePacketsLogs_Click;
        }

        #region ctxMenuPackets
        private void CopyChoosePayload_Click(object sender, EventArgs e)
        {
            if (Frm.lv_packet_log.SelectedItems.Count == 1)
            {
                string copied_payload = Frm.lv_packet_log.SelectedItems[0].SubItems[6].Text;
                if (!string.IsNullOrEmpty(copied_payload))
                {
                    Clipboard.SetText(copied_payload);
                }
            }
        }

        private void CopyWholePayload_Click(object sender, EventArgs e)
        {
            StringBuilder sb = new StringBuilder();
            foreach (ListViewItem item in Frm.lv_packet_log.Items)
            {
                if (item.Tag is PacketAnalyzer packet)
                {
                    sb.Append(packet.HexPayload);
                }
            }
            if (!string.IsNullOrEmpty(sb.ToString()))
            {
                Clipboard.SetText(sb.ToString());
            }
        }

        private void ReadCapturePacketsLogs_Click(object sender, EventArgs e)
        {
            OpenFileDialog file = new OpenFileDialog()
            {
                Title = "请选择抓包记录文件",
                InitialDirectory = Path.Combine(Directory.GetCurrentDirectory(), "data"),
                Filter = "所有文件(*.*)|*.*|文本文件(*.txt)|*.txt"
            };
            if (file.ShowDialog() == DialogResult.OK)
            {
                DisplayPacketLogListView(FileUtil.ReadString(file.FileName));
            }
        }

        private void SaveCapturePacketsLogs_Click(object sender, EventArgs e)
        {
            StringBuilder sb_all = new StringBuilder();
            foreach (ListViewItem item in Frm.lv_packet_log.Items)
            {
                string index = item.SubItems[0].Text;
                string orientation = item.SubItems[1].Text;
                string src = item.SubItems[2].Text;
                string dest = item.SubItems[3].Text;
                string capture_time = item.SubItems[4].Text;
                string payload_len = item.SubItems[5].Text;
                string payload = string.Empty;
                if (item.Tag is PacketAnalyzer analysisPacket)
                {
                    payload = analysisPacket.HexPayload;
                }
                //index orientation src dest capture_time payload_len payload
                string row = $"{index}---{orientation}---{src}---{dest}---{capture_time}---{payload_len}---{payload}";
                sb_all.Append(row).AppendLine();
            }
            if (string.IsNullOrEmpty(sb_all.ToString())) return;
            AppendTeaKeyLog(sb_all);
            if (!Directory.Exists("data")) Directory.CreateDirectory("data");
            string capture_log_filename = $"data/capture_log-{DateTime.Now:yyyy-MM-dd-HH-mm-ss}.txt";
            FileUtil.WriteString(capture_log_filename, sb_all.ToString());
        }

        private void DisplayPacketLogListView(string data)
        {
            Frm.lv_packet_log.Items.Clear();

            string[] rows = data.Split(Environment.NewLine.ToCharArray(), StringSplitOptions.RemoveEmptyEntries);
            List<ListViewItem> lvs = new List<ListViewItem>();
            rows.ToList().ForEach(row =>
            {
                string[] col = row.Split("---".ToCharArray(), StringSplitOptions.RemoveEmptyEntries);
                if (col.Length == 7)
                {
                    string index = col[0];
                    string orientation = col[1];
                    string src = col[2];
                    string dest = col[3];
                    string capture_time = col[4];
                    string payload_len = col[5];
                    string payload = col[6];
                    lvs.Add(new ListViewItem()
                    {
                        Text = index,
                        SubItems =
                        {
                            orientation,
                            src,
                            dest,
                            capture_time,
                            payload_len,
                            payload
                        },
                        Tag = new PacketAnalyzer() { HexPayload = payload, CaptureTime = capture_time },
                        ForeColor = (orientation == "Send") ? Color.Red : Color.Blue,
                    });
                }
                else if (col.Length == 5)
                {
                    DecryptionKey key = new DecryptionKey()
                    {
                        Key = col[0],
                        KeyType = (KeyType)Enum.Parse(typeof(KeyType), col[1]),
                        PrivateKey = col[3],
                        PublicKey = col[4]
                    };
                    Common.Keys.AddLast(key);
                }
            });

            Frm.lv_packet_log.Items.AddRange(lvs.ToArray());
        }

        private void AppendTeaKeyLog(StringBuilder sb)
        {
            List<DecryptionKey> keys = Common.GetTeaKeyLogSetList();
            keys.ToList()
                .ForEach(k =>
                {
                    string pri_key = string.IsNullOrEmpty(k.PrivateKey) ? "placeholder" : k.PrivateKey;
                    string pub_key = string.IsNullOrEmpty(k.PublicKey) ? "placeholder" : k.PublicKey;
                    sb.Append($"{k.Key}---{k.KeyType}---{k.KeyType.GetDisplayDescription()}---{pub_key}---{pri_key}").AppendLine();
                });
        }
        #endregion
    }
}
