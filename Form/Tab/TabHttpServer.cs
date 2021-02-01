using System;
using System.Threading;

namespace YgAndroidQQSniffer.Tab
{
    [Attributes.CustomEvent(nameof(TabHttpServer))]
    public class TabHttpServer : ICustomControlEvents
    {
        private static FormMain Frm { get => FormMain.Form; }
        public void Register()
        {
            Frm.btn_start_httpserver.Click += new EventHandler(Btn_start_httpserver_ClickAsync);
            Frm.btn_stop_httpserver.Click += new EventHandler(Btn_stop_httpserver_Click);
            Frm.btn_clean_httpserver_log.Click += new EventHandler(Btn_clean_httpserver_log_Click);
        }

        #region TAB HTTP服务器
        public HttpServer.HttpServer HttpServer { get; private set; }

        private async void Btn_start_httpserver_ClickAsync(object sender, EventArgs e)
        {
            string input = Frm.txt_httpserver_port.Text.Trim();
            if (string.IsNullOrEmpty(input) || !int.TryParse(input, out int port))
            {
                Toast.Warn("端口号格式不正确");
                return;
            }
            if (port < 0 || port <= 1024)
            {
                Toast.Warn("端口号应大于0且不小于1024");
                return;
            }
            try
            {
                if (HttpServer == null || HttpServer.SocketChannel.Open == false)
                {
                    HttpServer = new HttpServer.HttpServer() { Port = port };
                    HttpServer.SocketChannel = await HttpServer.StartAsync();
                    HttpServerLog("HTTP服务器启动成功");
                }
            }
            catch (Exception ex)
            {
                HttpServerLog("HTTP服务器启动失败 失败原因: {0}", ex.Message);
            }
        }

        private void Btn_stop_httpserver_Click(object sender, EventArgs e)
        {
            new Thread(() =>
            {
                if (HttpServer != null && HttpServer.SocketChannel.Open == true)
                {
                    Frm.ThreadSafeUpdate(() => Frm.btn_start_httpserver.Enabled = false);
                    Frm.ThreadSafeUpdate(() => Frm.btn_stop_httpserver.Enabled = false);
                    Frm.ThreadSafeUpdate(() => Frm.btn_stop_httpserver.Text = "关闭中");
                    if (HttpServer.Stop())
                    {
                        HttpServerLog("HTTP服务器关闭成功");
                        Frm.ThreadSafeUpdate(() => Frm.btn_start_httpserver.Enabled = true);
                        Frm.ThreadSafeUpdate(() => Frm.btn_stop_httpserver.Enabled = true);
                        Frm.ThreadSafeUpdate(() => Frm.btn_stop_httpserver.Text = "关闭");
                    }
                }
            }).Start();

        }

        private void Btn_clean_httpserver_log_Click(object sender, EventArgs e)
        {
            Frm.richTextBox_httpserver_log.Clear();
        }

        public static void HttpServerLog(string text)
        {
            string output = string.Format("{0} {1}{2}", DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"), text, Environment.NewLine);
            Frm.ThreadSafeUpdate(() => Frm.richTextBox_httpserver_log.AppendText(output));
        }

        public static void HttpServerLog(string text, params object[] args)
        {
            HttpServerLog(string.Format(text, args));
        }
        #endregion
    }
}
