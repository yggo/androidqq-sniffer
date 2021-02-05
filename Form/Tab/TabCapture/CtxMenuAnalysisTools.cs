/*
 *  Copyright 2021-2021 yggo Technologies and contributors.
 *
 *  此源代码的使用受 GNU AFFERO GENERAL PUBLIC LICENSE version 3 许可证的约束, 可以在以下链接找到该许可证.
 *  Use of this source code is governed by the GNU AGPLv3 license that can be found through the following link.
 *
 *  https://github.com/yggo/androidqq-sniffer/blob/main/LICENSE
 */

using DotNetty.Buffers;
using System;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows.Forms;
using YgAndroidQQSniffer.Component;

namespace YgAndroidQQSniffer.Tab.TabCapture
{
    [Attributes.CustomEvent(nameof(CtxMenuAnalysisTools))]
    public class CtxMenuAnalysisTools : ICustomControlEvents
    {
        private static FormMain Frm => FormMain.Form;

        public void Register()
        {
            Frm.计算字节数ToolStripMenuItem.Click += 计算字节数ToolStripMenuItem_Click;
            Frm.TLV格式化ToolStripMenuItem.Click += TLV格式化ToolStripMenuItem_Click;
            Frm.选中字节计算换行ToolStripMenuItem.Click += 选中字节计算换行ToolStripMenuItem_Click;
            Frm.一键格式化ToolStripMenuItem.Click += 一键格式化ToolStripMenuItem_Click;

            Frm.十六个0ToolStripMenuItem.Click += 十六个0ToolStripMenuItem_Click;
            Frm.kEY日志ToolStripMenuItem.Click += KEY日志ToolStripMenuItem_Click;

            Frm.到10进制ToolStripMenuItem1.Click += 到10进制ToolStripMenuItem1_Click;
            Frm.到文本ToolStripMenuItem.Click += 到文本ToolStripMenuItem_Click;
            Frm.到QQToolStripMenuItem.Click += 到QQToolStripMenuItem_Click;
            Frm.Dec到时间ToolStripMenuItem.Click += Dec到时间ToolStripMenuItem_Click;
            Frm.Hex到时间ToolStripMenuItem.Click += Hex到时间ToolStripMenuItem_Click;
            Frm.Hex到IPToolStripMenuItem.Click += Hex到IPToolStripMenuItem_Click;
            Frm.Inflater解压ToolStripMenuItem.Click += Inflater解压ToolStripMenuItem_Click;
        }

        #region 计算字节数
        private void 计算字节数ToolStripMenuItem_Click(object sender, EventArgs e)
        {
            string selected_text = Frm.r_txt_log.SelectedText.ClearSpecialSymbols();
            if (string.IsNullOrEmpty(selected_text)) return;
            if (selected_text.Length % 2 != 0)
            {
                Toast.Warn("请选择完整字节");
                return;
            }
            if (!Regex.IsMatch(selected_text, "^[0-9a-fA-F]+$"))
            {
                Toast.Warn("字节数据不合法");
                return;
            }
            Toast.Info((selected_text.Length / 2).ToString());
        }
        #endregion

        #region TLV 格式化
        private void TLV格式化ToolStripMenuItem_Click(object sender, EventArgs e)
        {
            string selected_text = Frm.r_txt_log.SelectedText.ClearSpecialSymbols();
            if (string.IsNullOrEmpty(selected_text)) return;
            try
            {
                var buf = Unpooled.WrappedBuffer(selected_text.DecodeHex());
                string ret = new TLVParser.TLVFormatter().Parse(buf);
                Frm.Log($"\n{ret}\n");
                Console.WriteLine(ret);
            }
            catch (Exception ex)
            {
                Toast.Failed(ex.Message);
                Console.WriteLine(ex.Message);
            }
        }
        #endregion

        #region 选中字节计算换行
        private void 选中字节计算换行ToolStripMenuItem_Click(object sender, EventArgs e)
        {
            //TODO 选中两个字节到10进制计算没问题，如果是选中四个字节(int)再去计算就有问题
            string selected_text = Frm.r_txt_log.SelectedText.Replace("\r", "").Replace("\n", "");
            if (string.IsNullOrEmpty(selected_text)) return;

            string old_text = Clipboard.GetText();
            int old_start = Frm.r_txt_log.SelectionStart;
            int old_length = Frm.r_txt_log.SelectionLength;
            try
            {
                long calc_len = selected_text.HexToDec();
                Frm.r_txt_log.SelectionStart = ((int)calc_len * 3) + old_start + old_length;
                Frm.r_txt_log.SelectionLength = 0;
                Clipboard.SetText(Environment.NewLine + Environment.NewLine);
                Frm.r_txt_log.Paste();
                Clipboard.SetText(old_text);
            }
            catch (Exception)
            {
                // ignored
            }
        }
        #endregion

        #region 一键格式化
        private void 一键格式化ToolStripMenuItem_Click(object sender, EventArgs e)
        {
            string selected_text = Frm.r_txt_log.Text.ClearSpecialSymbols();
            if (string.IsNullOrEmpty(selected_text)) return;
            string ret = new PacketFormatter().Parse(Unpooled.WrappedBuffer(selected_text.DecodeHex()));
            Frm.Log("\n\n{0}\n\n", ret);
        }
        #endregion

        #region TEA解密 右键菜单

        private void 十六个0ToolStripMenuItem_Click(object sender, EventArgs e)
        {
            try
            {
                byte[] data = Frm.r_txt_log.SelectedText.DecodeHex();
                byte[] decrypt_data = Common.TeaKeyLogDecrypt(data, out DecryptionKey decryptionKey);
                if (decrypt_data != null)
                {
                    Frm.Log(Common.PrettyKeyDecryptDump(decrypt_data, decryptionKey));
                }
            }
            catch (Exception ex)
            {
                Toast.Failed(ex.Message);
            }
        }

        private void KEY日志ToolStripMenuItem_Click(object sender, EventArgs e)
        {
            string selected_text = Frm.r_txt_log.SelectedText.ClearSpecialSymbols();
            if (string.IsNullOrEmpty(selected_text)) return;
            byte[] decrypt_data = Common.TeaKeyLogDecrypt(selected_text.DecodeHex(), out DecryptionKey decryptionKey);
            if (decrypt_data != null)
            {
                Frm.Log(Common.PrettyKeyDecryptDump(decrypt_data, decryptionKey));
            }
        }

        #endregion

        #region 右键菜单 转换
        private void 到10进制ToolStripMenuItem1_Click(object sender, EventArgs e)
        {
            string selected_text = Frm.r_txt_log.SelectedText.ClearSpecialSymbols();
            if (string.IsNullOrEmpty(selected_text)) return;
            try
            {
                string str = $" //[Dec: {selected_text.HexToDec()}]";
                Frm.Log(str);
            }
            catch (Exception ex)
            {
                Toast.Failed(ex.Message);
            }
        }
        private void 到文本ToolStripMenuItem_Click(object sender, EventArgs e)
        {
            string selected_text = Frm.r_txt_log.SelectedText.ClearSpecialSymbols();
            if (string.IsNullOrEmpty(selected_text)) return;
            try
            {
                string str = $" //[Text: {selected_text.DecodeHex().HexToString(Encoding.UTF8)}]";
                Console.WriteLine(str);
                Frm.Log(str);
            }
            catch (Exception ex)
            {
                Toast.Failed(ex.Message);
            }
        }

        private void 到QQToolStripMenuItem_Click(object sender, EventArgs e)
        {
            string selected_text = Frm.r_txt_log.SelectedText.ClearSpecialSymbols();
            if (string.IsNullOrEmpty(selected_text)) return;
            try
            {
                string ret = $" //[QQ: {selected_text.HexToDec()}]";
                Frm.Log(ret);
            }
            catch (Exception ex)
            {
                Toast.Failed(ex.Message);
            }
        }

        private void Dec到时间ToolStripMenuItem_Click(object sender, EventArgs e)
        {
            string selected_text = Frm.r_txt_log.SelectedText.ClearSpecialSymbols();
            if (string.IsNullOrEmpty(selected_text)) return;
            try
            {
                Frm.Log($" //[Time: {double.Parse(selected_text).UnixTimeStampToDateTime()}]");
            }
            catch (Exception ex)
            {
                Toast.Failed(ex.Message);
            }
        }

        private void Hex到时间ToolStripMenuItem_Click(object sender, EventArgs e)
        {
            string selected_text = Frm.r_txt_log.SelectedText.ClearSpecialSymbols();
            if (string.IsNullOrEmpty(selected_text)) return;
            try
            {
                string ret = $" //[Time: {selected_text.HexToDateTime()}]";
                Frm.Log(ret);
            }
            catch (Exception ex)
            {
                Toast.Failed(ex.Message);
            }
        }

        private void Hex到IPToolStripMenuItem_Click(object sender, EventArgs e)
        {
            string selected_text = Frm.r_txt_log.SelectedText.ClearSpecialSymbols();
            if (string.IsNullOrEmpty(selected_text)) return;
            try
            {
                Frm.Log($" //[Ip: {selected_text.HexToDec().LongToIpEndian()}]");
            }
            catch (Exception ex)
            {
                Toast.Failed(ex.Message);
            }
        }

        private void Inflater解压ToolStripMenuItem_Click(object sender, EventArgs e)
        {
            string selected_text = Frm.r_txt_log.Text.ClearSpecialSymbols();
            if (string.IsNullOrEmpty(selected_text)) return;

            try
            {
                using MemoryStream compressedStream = new MemoryStream(selected_text.DecodeHex());
                using DeflateStream deflateStream = new DeflateStream(compressedStream, CompressionMode.Decompress);
                using MemoryStream outputStream = new MemoryStream();
                deflateStream.CopyTo(outputStream);
                Frm.Log($"\n\n[{outputStream.ToArray().HexDump()}]\n\n");
                /*using (var inputStream = new InflaterInputStream(compressedStream))
                {
                    inputStream.CopyTo(outputStream);
                    outputStream.Position = 0;
                    Log($"\n\n[{outputStream.ToArray().HexDump()}]\n\n");
                }*/
            }
            catch (Exception)
            {
                // ignored
            }
        }
        #endregion
    }
}
