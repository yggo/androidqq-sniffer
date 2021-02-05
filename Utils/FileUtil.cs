/*
 *  Copyright 2021-2021 yggo Technologies and contributors.
 *
 *  此源代码的使用受 GNU AFFERO GENERAL PUBLIC LICENSE version 3 许可证的约束, 可以在以下链接找到该许可证.
 *  Use of this source code is governed by the GNU AGPLv3 license that can be found through the following link.
 *
 *  https://github.com/yggo/androidqq-sniffer/blob/main/LICENSE
 */

using System.IO;
using System.Text;

namespace YgAndroidQQSniffer
{
    public class FileUtil
    {
        public static string ReadString(string filename)
        {
            using FileStream fs = new FileStream(filename, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            byte[] buffer = new byte[fs.Length];
            fs.Read(buffer, 0, (int)fs.Length);
            return Encoding.UTF8.GetString(buffer);
        }

        public static void WriteString(string filename, string content)
        {
            using FileStream fs = new FileStream(filename, FileMode.Create, FileAccess.Write, FileShare.ReadWrite);
            byte[] buf = Encoding.UTF8.GetBytes(content);
            fs.Write(buf, 0, buf.Length);
        }
    }
}
