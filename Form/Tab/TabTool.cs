using DotNetty.Buffers;
using DotNetty.Common.Utilities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows.Forms;

namespace YgAndroidQQSniffer.Tab
{
    [Attributes.CustomEvent(nameof(TabTool))]
    public class TabTool : ICustomControlEvents
    {
        private static FormMain Frm { get => FormMain.Form; }

        public void Register()
        {
            Frm.btn_tool_read_keys.Click += new EventHandler(Btn_tool_read_keys_Click);
            Frm.btn_tool_save_keys.Click += new EventHandler(Btn_tool_save_keys_Click);
            Frm.btn_tool_md5_calc.Click += new EventHandler(Btn_tool_md5_calc_Click);
            Frm.btn_tool_md5_copy_once.Click += new EventHandler(Btn_tool_md5_copy_once_Click);
            Frm.btn_tool_qqencrypt_calc.Click += new EventHandler(Btn_tool_qqencrypt_calc_Click);
            Frm.btn_tool_qqencrypt_copy.Click += new EventHandler(Btn_tool_qqencrypt_copy_Click);
            Frm.btn_tool_hookdata_showPwd.Click += new EventHandler(Btn_tool_hookdata_showPwd_Click);
        }

        #region TAB 工具
        #region KEY日志
        private void Btn_tool_read_keys_Click(object sender, EventArgs e)
        {
            List<DecryptionKey> keys = Common.GetTeaKeyLogSetList();
            string text = string.Empty;
            keys.ForEach(k => text += k.Key + Environment.NewLine);
            Frm.txt_tool_keys.Text = text;
        }

        private void Btn_tool_save_keys_Click(object sender, EventArgs e)
        {
            string keys_text = Frm.txt_tool_keys.Text;
            string[] keys = keys_text.Split(new char[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            HashSet<string> key_set = new HashSet<string>();
            Common.Keys.Clear();
            keys.ToList().ForEach(k => key_set.Add(k));
            key_set.ToList().ForEach(k => Common.Keys.AddLast(new DecryptionKey() { Key = k, KeyType = KeyType.CUSTOM_KEY }));
        }
        #endregion

        #region MD5计算
        private void Btn_tool_md5_calc_Click(object sender, EventArgs e)
        {
            Frm.txt_tool_md5_once.Text = Frm.txt_tool_md5_input.Text.Md5().HexDump(); ;
        }

        private void Btn_tool_md5_copy_once_Click(object sender, EventArgs e)
        {
            string ret = Frm.txt_tool_md5_once.Text;
            if (!string.IsNullOrEmpty(ret))
            {
                Clipboard.SetText(Frm.txt_tool_md5_once.Text);
            }
        }
        #endregion

        #region QQ密码加密
        private void Btn_tool_qqencrypt_calc_Click(object sender, EventArgs e)
        {
            string qq = Frm.txt_tool_qqencrypt_qq.Text;
            string pass = Frm.txt_tool_qqencrypt_pass.Text;
            var buf = Unpooled.Buffer();
            try
            {
                buf.WriteBytes(Util.GenerateMD5Byte(pass))
                .WriteInt(0)
                .WriteInt((int)Convert.ToInt64(qq));

                Frm.txt_tool_qqencrypt_ret.Text = buf.Copy().Array.Md5().HexDump();
            }
            catch (Exception ex)
            {
                Toast.Warn(ex.Message);
            }
            finally
            {
                ReferenceCountUtil.Release(buf);
            }
        }

        private void Btn_tool_qqencrypt_copy_Click(object sender, EventArgs e)
        {
            string ret = Frm.txt_tool_qqencrypt_ret.Text;
            if (!string.IsNullOrEmpty(ret))
            {
                Clipboard.SetText(Frm.txt_tool_qqencrypt_ret.Text);
            }
        }
        #endregion

        #region Hook数据
        private void Btn_tool_hookdata_showPwd_Click(object sender, EventArgs e)
        {
            if (sender is Button btn)
            {
                if (btn.Text == "显示")
                {
                    btn.Text = "隐藏";
                    Frm.txt_tool_hookdata_pwd.PasswordChar = Convert.ToChar(0);
                }
                else
                {
                    btn.Text = "显示";
                    Frm.txt_tool_hookdata_pwd.PasswordChar = '*';
                }
            }

        }
        #endregion

        #endregion
    }
}
