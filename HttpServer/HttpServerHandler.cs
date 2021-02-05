/*
 *  Copyright 2021-2021 yggo Technologies and contributors.
 *
 *  此源代码的使用受 GNU AFFERO GENERAL PUBLIC LICENSE version 3 许可证的约束, 可以在以下链接找到该许可证.
 *  Use of this source code is governed by the GNU AGPLv3 license that can be found through the following link.
 *
 *  https://github.com/yggo/androidqq-sniffer/blob/main/LICENSE
 */

using DotNetty.Buffers;
using DotNetty.Codecs.Http;
using DotNetty.Codecs.Http.Multipart;
using DotNetty.Common;
using DotNetty.Common.Utilities;
using DotNetty.Transport.Channels;
using NLog;
using System;
using System.Collections.Concurrent;
using System.Text;

namespace YgAndroidQQSniffer.HttpServer
{
    public class HttpServerHandler : SimpleChannelInboundHandler<IFullHttpRequest>
    {
        static readonly ThreadLocalCache Cache = new ThreadLocalCache();
        public static Logger Logger { get; set; } = LogManager.GetCurrentClassLogger();
        sealed class ThreadLocalCache : FastThreadLocal<AsciiString>
        {
            protected override AsciiString GetInitialValue()
            {
                DateTime dateTime = DateTime.Now;
                return AsciiString.Cached($"{dateTime.DayOfWeek}, {dateTime:dd MMM yyyy HH:mm:ss z}");
            }
        }

        static readonly AsciiString TypePlain = AsciiString.Cached("text/plain");
        static readonly AsciiString ServerName = AsciiString.Cached("YgAndroidQQSniffer");
        static readonly AsciiString ContentTypeEntity = HttpHeaderNames.ContentType;
        static readonly AsciiString DateEntity = HttpHeaderNames.Date;
        static readonly AsciiString ContentLengthEntity = HttpHeaderNames.ContentLength;
        static readonly AsciiString ServerEntity = HttpHeaderNames.Server;
        static readonly BlockingCollection<string> _keys = new BlockingCollection<string>();

        static readonly string HookMethodName = "methodName";
        static readonly string HookMethodValue = "methodValue";

        volatile ICharSequence Date = Cache.Value;

        void WriteResponse(IChannelHandlerContext ctx, IByteBuffer buf, ICharSequence contentType, ICharSequence contentLength)
        {
            var response = new DefaultFullHttpResponse(HttpVersion.Http11, HttpResponseStatus.OK, buf, false);
            HttpHeaders headers = response.Headers;
            headers.Set(ContentTypeEntity, contentType);
            headers.Set(ServerEntity, ServerName);
            headers.Set(DateEntity, Date);
            headers.Set(ContentLengthEntity, contentLength);
            ctx.WriteAsync(response);
        }

        public override void ExceptionCaught(IChannelHandlerContext context, Exception exception) => context.CloseAsync();

        public override void ChannelReadComplete(IChannelHandlerContext context) => context.Flush();

        protected override void ChannelRead0(IChannelHandlerContext ctx, IFullHttpRequest msg)
        {
            if (msg.Method == HttpMethod.Post)
            {
                var decoder = new HttpPostRequestDecoder(msg);
                decoder.Offer(msg);
                string hookMethodName = string.Empty;
                string hookMethodValue = string.Empty;
                decoder.GetBodyHttpDatas().ForEach(httpData =>
                {
                    var param = (IAttribute)httpData;
                    if (param.Name == HookMethodName)
                    {
                        hookMethodName = param.Value;
                    }
                    if (param.Name == HookMethodValue)
                    {
                        hookMethodValue = param.Value;
                    }
                });
                if (!string.IsNullOrEmpty(hookMethodName) && !string.IsNullOrEmpty(hookMethodValue))
                {
                    Console.WriteLine(hookMethodName + "---" + hookMethodValue);
                    switch (hookMethodName)
                    {
                        case "getAndroidId":
                            HookData.AndroidId = hookMethodValue;
                            break;
                        case "getMacAddr":
                            HookData.Mac = hookMethodValue;
                            break;
                        case "get_bssid_addr":
                            HookData.BSSID = hookMethodValue;
                            break;
                        case "get_qimei":
                            HookData.IMEI = hookMethodValue;
                            break;
                        case "get_IMSI":
                            HookData.IMSI = hookMethodValue;
                            break;
                        case "A1":
                            HookData.A1 = hookMethodValue;
                            break;
                        case "A2":
                            HookData.A2 = hookMethodValue;
                            break;
                        case "A3":
                            HookData.A3 = hookMethodValue;
                            break;
                        case "nick":
                            HookData.Nick = hookMethodValue;
                            break;
                        case "D2KEY":
                            HookData.D2KEY = hookMethodValue;
                            Common.Keys.AddLast(new DecryptionKey() { Key = hookMethodValue, KeyType = KeyType.D2_KEY });
                            break;
                        case "tgtkey":
                            HookData.TGTKEY = hookMethodValue;
                            Common.Keys.AddLast(new DecryptionKey() { Key = hookMethodValue, KeyType = KeyType.RAND_TGT_KEY });
                            break;
                        case "LoginPwd":
                            HookData.Pwd = hookMethodValue;
                            break;
                        default:
                            break;
                    }

                    if (hookMethodName == "set_g_share_key")
                    {
                        if (_keys.Count >= 2)
                        {
                            Common.Keys.AddLast(new DecryptionKey() { Key = hookMethodValue, KeyType = KeyType.SHARE_KEY, PublicKey = _keys.Take(), PrivateKey = _keys.Take() });
                        }
                        else
                        {
                            Common.Keys.AddLast(new DecryptionKey() { Key = hookMethodValue, KeyType = KeyType.SHARE_KEY });
                            Logger.Warn("set_g_share_key 队列剩余容量不足!");
                        }
                    }

                    if (hookMethodName == "set_c_pub_key" || hookMethodName == "set_c_pri_key")
                    {
                        _keys.Add(hookMethodValue);
                    }

                    if (hookMethodName == "Cryptor.encrypt" || hookMethodName == "Cryptor.decrypt")
                    {
                        Common.Keys.AddLast(new DecryptionKey() { Key = hookMethodValue, KeyType = KeyType.CACHED_SHAKEY });
                    }

                    if (hookMethodName == "set_c_pub_key" || hookMethodName == "set_c_pri_key"
                        || hookMethodName == "set_g_share_key" || hookMethodName == "GenECDHKeyEx"
                        || hookMethodName == "SetSigInfo" || hookMethodName == "Cryptor.encrypt"
                        || hookMethodName == "Cryptor.decrypt" || hookMethodName == "test"
                        || hookMethodName == "LoginPwd" || hookMethodName == "calShareKeyByBouncycastle"
                        || hookMethodName == "InitShareKeyByBouncycastle")
                    {
                        Tab.TabHttpServer.HttpServerLog("hookMethodName: {0} hookMethodValue: {1}", hookMethodName, hookMethodValue);
                    }
                }
            }

            byte[] content = Encoding.UTF8.GetBytes("http server is ok");
            WriteResponse(ctx, Unpooled.WrappedBuffer(content), TypePlain, AsciiString.Cached(content.Length.ToString()));
        }
    }
}
