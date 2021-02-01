using System.Windows.Forms;
using YgAndroidQQSniffer.Extension;

namespace YgAndroidQQSniffer
{
    public class Toast
    {
        public static void Success(string text, string caption = "提示")
        {

            MessageBoxEx.Show(FormMain.Form, text, caption, MessageBoxButtons.OK, MessageBoxIcon.Asterisk);
        }

        public static void Failed(string text, string caption = "提示")
        {
            MessageBoxEx.Show(FormMain.Form, text, caption, MessageBoxButtons.OK, MessageBoxIcon.Error);
        }

        public static void Warn(string text, string caption = "提示")
        {
            MessageBoxEx.Show(FormMain.Form, text, caption, MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
        public static void Info(string text, string caption = "提示")
        {
            MessageBoxEx.Show(FormMain.Form, text, caption, MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
    }
}
