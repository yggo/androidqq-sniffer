/*
 *  Copyright 2021-2021 yggo Technologies and contributors.
 *
 *  此源代码的使用受 GNU AFFERO GENERAL PUBLIC LICENSE version 3 许可证的约束, 可以在以下链接找到该许可证.
 *  Use of this source code is governed by the GNU AGPLv3 license that can be found through the following link.
 *
 *  https://github.com/yggo/androidqq-sniffer/blob/main/LICENSE
 */

using DotNetty.Buffers;
using System.Diagnostics;
using System.IO;
using YgAndroidQQSniffer.TLVParser;

namespace YgAndroidQQSniffer.PbParser
{
    public class PbFormatter : IParser
    {
        public string Parse(IByteBuffer value)
        {
            using Process process = new Process();
            process.StartInfo.FileName = "cmd.exe";
            // 是否使用操作系统shell启动
            process.StartInfo.UseShellExecute = false;
            // 接收来自调用程序的输入信息
            process.StartInfo.RedirectStandardInput = true;
            // 由调用程序获取输出信息
            process.StartInfo.RedirectStandardOutput = true;
            // 重定向标准错误输出
            process.StartInfo.RedirectStandardError = true;
            // 不显示程序窗口
            process.StartInfo.CreateNoWindow = true;

            process.Start();

            //process.StandardInput.WriteLine(@"C:\Users\yggo\Desktop\protoc.exe --decode_raw < G:\C#WorkSpace\EpointMsgReverse\bin\Debug\test.bin&exit");
            process.StandardInput.WriteLine(@"C:\Users\yggo\Desktop\protoc.exe --decode_raw < " + WriteTmpBinFile(value) + "&exit");

            process.StandardInput.AutoFlush = true;
            // Synchronously read the standard output of the spawned process.
            StreamReader reader = process.StandardOutput;
            string output = reader.ReadToEnd();

            process.WaitForExit();
            // Write the redirected output to this application's window.
            return output;
        }

        private string WriteTmpBinFile(IByteBuffer value)
        {
            string tempFile = Path.GetTempFileName();
            using (BinaryWriter bw = new BinaryWriter(File.OpenWrite(tempFile)))
            {
                bw.Write(value.ReadRemainingBytes());
            }
            return tempFile;
        }
    }
}
