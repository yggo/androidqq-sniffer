/*
 *  Copyright 2021-2021 yggo Technologies and contributors.
 *
 *  此源代码的使用受 GNU AFFERO GENERAL PUBLIC LICENSE version 3 许可证的约束, 可以在以下链接找到该许可证.
 *  Use of this source code is governed by the GNU AGPLv3 license that can be found through the following link.
 *
 *  https://github.com/yggo/androidqq-sniffer/blob/main/LICENSE
 */

using DotNetty.Transport.Bootstrapping;
using DotNetty.Transport.Channels;
using DotNetty.Transport.Channels.Sockets;
using System.Net;
using System.Threading.Tasks;

namespace YgAndroidQQSniffer.HttpServer
{
    public class HttpServer
    {
        public int Port { get; set; } = 8899;
        public IChannel SocketChannel { get; set; }
        private IEventLoopGroup Boss;
        private IEventLoopGroup Work;

        public async Task<IChannel> StartAsync()
        {
            ServerBootstrap bootstrap = new ServerBootstrap();
            Boss = new MultithreadEventLoopGroup(1);
            Work = new MultithreadEventLoopGroup(2);
            bootstrap.Group(Boss, Work)
                .Channel<TcpServerSocketChannel>()
                .Option(ChannelOption.SoBacklog, 8192)
                .ChildHandler(new HttpServerInitializer());

            return await bootstrap.BindAsync(IPAddress.Any, Port);
        }

        public bool Stop()
        {
            if (Boss != null && Work != null && SocketChannel != null)
            {
                Task.WaitAll(SocketChannel.CloseAsync(), Boss.ShutdownGracefullyAsync(), Work.ShutdownGracefullyAsync());
                return true;
            }
            return false;
        }
    }
}
