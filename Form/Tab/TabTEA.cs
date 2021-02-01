using System;
using System.Windows.Forms;

namespace YgAndroidQQSniffer.Tab
{
    [Attributes.CustomEvent(nameof(TabTEA))]
    public class TabTEA : ICustomControlEvents
    {
        private static FormMain Frm { get => FormMain.Form; }

        public void Register()
        {
            Frm.btn_tea_encrypt.Click += new EventHandler(Btn_tea_encrypt_Click);
            Frm.btn_tea_decrypt.Click += new EventHandler(Btn_tea_decrypt_Click);
            Frm.btn_tea_copy_decrypt_data.Click += new EventHandler(Btn_tea_copy_decrypt_data_Click);
            Frm.btn_tea_key_log_decrypt.Click += new EventHandler(Btn_tea_key_log_decrypt_Click);
            Frm.btn_decrypt_byte_by_byte.Click += new EventHandler(Btn_decrypt_byte_by_byte_Click);
        }

        #region TAB TEA加解密
        private void Btn_tea_encrypt_Click(object sender, EventArgs e)
        {
            try
            {
                byte[] key = HexUtil.DecodeHex(Frm.txt_tea_key.Text);
                byte[] data = HexUtil.DecodeHex(Frm.txt_tea_encrypt_data.Text);
                byte[] ret = Tea.Encrypt(data, key);
                if (ret != null)
                {
                    Frm.txt_tea_decrypt_data.Text = ret.HexDump();
                }
            }
            catch (Exception) { }
        }

        private void Btn_tea_decrypt_Click(object sender, EventArgs e)
        {
            try
            {
                byte[] key = HexUtil.DecodeHex(Frm.txt_tea_key.Text);
                byte[] data = HexUtil.DecodeHex(Frm.txt_tea_encrypt_data.Text);
                byte[] ret = Tea.Decrypt(data, key);
                if (ret != null)
                {
                    Frm.txt_tea_decrypt_data.Text = ret.HexDump();
                }
            }
            catch (Exception) { }
        }

        private void Btn_tea_copy_decrypt_data_Click(object sender, EventArgs e)
        {
            string ret = Frm.txt_tea_decrypt_data.Text;
            if (!string.IsNullOrEmpty(ret))
            {
                Clipboard.SetText(ret);
            }
        }

        private void Btn_tea_key_log_decrypt_Click(object sender, EventArgs e)
        {
            string encrypt_data = Frm.txt_tea_encrypt_data.Text;
            if (string.IsNullOrEmpty(encrypt_data)) return;
            byte[] data = HexUtil.DecodeHex(encrypt_data);
            byte[] decrypt_data = Common.TeaKeyLogDecrypt(data, out DecryptionKey decryptionKey);
            if (decrypt_data != null)
            {
                Frm.txt_tea_decrypt_data.Text = decrypt_data.HexDump();
                Frm.txt_tea_key.Text = decryptionKey.Key;
            }
        }

        private void Btn_decrypt_byte_by_byte_Click(object sender, EventArgs e)
        {
            string encrypt_data = Frm.txt_tea_encrypt_data.Text.ClearSpecialSymbols();
            if (string.IsNullOrEmpty(encrypt_data)) return;
            for (int i = 0; i < encrypt_data.Length; i+=2)
            {
                byte[] data = encrypt_data.Substring(i, encrypt_data.Length - i).DecodeHex();
                byte[] decrypt_data = Common.TeaKeyLogDecrypt(data, out DecryptionKey decryptionKey);
                if (decrypt_data != null)
                {
                    Frm.txt_tea_decrypt_data.Text = decrypt_data.HexDump();
                    Frm.txt_tea_key.Text = decryptionKey.Key;
                    Toast.Info($"逐字节KEY日志解密成功, 共读取了[{i}]个字节长度");
                    return;
                }
            }
            Toast.Info("逐字节KEY日志解密失败, 未找到匹配的数据");
        }
        #endregion
    }
}
