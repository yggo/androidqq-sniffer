/*
 *  Copyright 2021-2021 yggo Technologies and contributors.
 *
 *  此源代码的使用受 GNU AFFERO GENERAL PUBLIC LICENSE version 3 许可证的约束, 可以在以下链接找到该许可证.
 *  Use of this source code is governed by the GNU AGPLv3 license that can be found through the following link.
 *
 *  https://github.com/yggo/androidqq-sniffer/blob/main/LICENSE
 */

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
