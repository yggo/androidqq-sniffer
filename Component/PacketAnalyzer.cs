using DotNetty.Buffers;
using System;
using System.Text;

namespace YgAndroidQQSniffer.Component
{
    public class PacketAnalyzer
    {
        public string Orientation { get; private set; } = "Send";
        public string ServiceCmd { get; private set; }
        public string SSOReq { get; private set; }
        private string _uin;
        public string Uin { get => _uin; private set { _uin = value; HookData.Uin = _uin; } }
        /// <summary>
        /// 数据包被捕获的时间
        /// </summary>
        public string CaptureTime { get; set; }
        public byte[] Payload { get; set; }
        public string HexPayload { get; set; }//包括4字节包大小 分包那里需要 需要改进
        private IByteBuffer Buf { get; set; }

        public void Deserialize()
        {
            HexPayload = Payload.HexDump();
            Buf = Unpooled.WrappedBuffer(Payload);
            Buf.ReadInt();//pkg_len
            int packet_type = Buf.ReadInt();
            byte encrypt_type = Buf.ReadByte();
            if (packet_type == 0x0A)
            {
                if (encrypt_type == 0x01)
                {
                    Resolve0A01();
                }
                else if (encrypt_type == 0x02)
                {
                    Resolve0A02();
                }
                else if (encrypt_type == 0x00)
                {
                    Resolve0A00();
                }
                else
                {
                    throw new InvalidOperationException("invalid encrypt_type: " + encrypt_type.HexPadLeft());
                }
            }
            else if (packet_type == 0x0B)
            {
                if (encrypt_type == 0x01)
                {
                    Resolve0B01();
                }
                else if (encrypt_type == 0x02)
                {
                    Resolve0B02();
                }
                else if (encrypt_type == 0x00)
                {
                    Resolve0B00();
                }
                else
                {
                    throw new InvalidOperationException("invalid encrypt_type: " + encrypt_type.HexPadLeft());
                }
            }
            else
            {
                throw new InvalidOperationException("invalid packet_type: " + encrypt_type.HexPadLeft());
            }
        }

        protected void Resolve0A01()
        {
            if (Buf.GetInt(Buf.ReaderIndex) == 0x00)
            {
                Orientation = "Recv";
                Buf.ReadByte();
            }
            else
            {
                int d2_len = Buf.ReadInt() - 4;
                Buf.ReadBytes(d2_len);
                Buf.ReadByte();
            }
            int qq_len = Buf.ReadInt() - 4;
            Uin = Buf.ReadCharSequence(qq_len, Encoding.UTF8).ToString();
            byte[] remaining = Util.ReadRemainingBytes(Buf);
            byte[] decrypt_data = Common.TeaKeyLogDecrypt(remaining, out _);
            if (decrypt_data == null) return;
            var buf_part1 = Unpooled.WrappedBuffer(decrypt_data);
            buf_part1.ReadInt();
            SSOReq = buf_part1.ReadUnsignedInt().ToString();
            if (buf_part1.GetInt(buf_part1.ReaderIndex) == 0x00)
            {
                Orientation = "Recv";
                buf_part1.ReadInt();
                buf_part1.ReadInt();
            }
            else
            {
                buf_part1.ReadInt();//appid
                buf_part1.ReadInt();//appid
                buf_part1.ReadBytes(12);//fixed
                if (buf_part1.GetInt(buf_part1.ReaderIndex) == 0x4C)
                {
                    int tgt_len = buf_part1.ReadInt() - 4;
                    buf_part1.ReadBytes(tgt_len);
                }
                else
                {
                    buf_part1.ReadInt();
                }
            }

            int service_cmd_len = buf_part1.ReadInt() - 4;
            ServiceCmd = buf_part1.ReadCharSequence(service_cmd_len, Encoding.UTF8).ToString();
        }

        protected void Resolve0A02()
        {
            if (Buf.GetInt(Buf.ReaderIndex) == 0x04)
            {
                Buf.ReadInt();
            }
            Buf.ReadByte();
            int qq_len = Buf.ReadInt() - 4;
            Uin = Buf.ReadCharSequence(qq_len, Encoding.UTF8).ToString();
            byte[] remaining = Util.ReadRemainingBytes(Buf);
            byte[] decrypt_data = Tea.Decrypt(remaining, new byte[16]);
            if (decrypt_data == null) return;
            var buf_part1 = Unpooled.WrappedBuffer(decrypt_data);
            buf_part1.ReadInt();
            SSOReq = buf_part1.ReadUnsignedInt().ToString();
            if (buf_part1.GetInt(buf_part1.ReaderIndex) == 0x00)
            {
                Orientation = "Recv";
                buf_part1.ReadInt();
                buf_part1.ReadInt();
            }
            else
            {
                buf_part1.ReadInt();//appid
                buf_part1.ReadInt();//appid
                buf_part1.ReadBytes(12);//fixed
                if (buf_part1.GetInt(buf_part1.ReaderIndex) == 0x4C)
                {
                    int tgt_len = buf_part1.ReadInt();
                    buf_part1.ReadBytes(tgt_len - 4);
                }
                else
                {
                    buf_part1.ReadInt();
                }
            }

            int service_cmd_len = buf_part1.ReadInt() - 4;
            ServiceCmd = buf_part1.ReadCharSequence(service_cmd_len, Encoding.UTF8).ToString();
        }

        protected void Resolve0A00()
        {
            if (Buf.GetInt(Buf.ReaderIndex) == 0x00)
            {
                Orientation = "Recv";
                Buf.ReadByte();
            }
            else
            {
                Buf.ReadInt();
                Buf.ReadByte();
            }
            int qq_len = Buf.ReadInt() - 4;
            Buf.ReadBytes(qq_len);//0A 00这里不是QQ 只有1个字节数据0x30 先取这个变量名
            Buf.ReadInt();//bodySize
            SSOReq = Buf.ReadUnsignedInt().ToString();
            if (Buf.GetInt(Buf.ReaderIndex) == 0x00)
            {
                Buf.ReadInt();
                Buf.ReadInt();
            }
            else
            {
                Buf.ReadInt();//appid
                Buf.ReadInt();//subAppid
                Buf.ReadBytes(12);//fixed
                Buf.ReadInt();//0x04
            }
            int service_cmd_len = Buf.ReadInt() - 4;
            ServiceCmd = Buf.ReadCharSequence(service_cmd_len, Encoding.UTF8).ToString();
        }

        protected void Resolve0B01()
        {
            if (Buf.GetInt(Buf.ReaderIndex) == 0x00)
            {
                Orientation = "Recv";
            }
            else
            {
                SSOReq = Buf.ReadUnsignedInt().ToString();
            }
            Buf.ReadByte();
            int qq_len = Buf.ReadInt() - 4;
            Uin = Buf.ReadCharSequence(qq_len, Encoding.UTF8).ToString();
            byte[] remaining = Util.ReadRemainingBytes(Buf);
            byte[] decrypt_data = Common.TeaKeyLogDecrypt(remaining, out _);
            if (decrypt_data == null) return;
            var buf_part1 = Unpooled.WrappedBuffer(decrypt_data);
            buf_part1.ReadInt();//head_size
            if (buf_part1.GetInt(buf_part1.ReaderIndex + 4) == 0x00)
            {
                //recv
                SSOReq = buf_part1.ReadUnsignedInt().ToString();
                buf_part1.ReadInt();//0x00
                buf_part1.ReadInt();//0x04
            }
            int service_cmd_len = buf_part1.ReadInt() - 4;
            ServiceCmd = buf_part1.ReadCharSequence(service_cmd_len, Encoding.UTF8).ToString();
        }

        protected void Resolve0B02()
        {
            if (Buf.GetInt(Buf.ReaderIndex) == 0x00)
            {
                Orientation = "Recv";
                Buf.ReadByte();
                int qq_len = Buf.ReadInt() - 4;
                Uin = Buf.ReadCharSequence(qq_len, Encoding.UTF8).ToString();
                byte[] remaining = Util.ReadRemainingBytes(Buf);
                byte[] decrypt_data = Tea.Decrypt(remaining, new byte[16]);
                if (decrypt_data == null) return;
                var buf_part1 = Unpooled.WrappedBuffer(decrypt_data);
                buf_part1.ReadInt();
                SSOReq = buf_part1.ReadUnsignedInt().ToString();
                buf_part1.ReadInt();
                buf_part1.ReadInt();
                int service_cmd_len = buf_part1.ReadInt() - 4;
                ServiceCmd = buf_part1.ReadCharSequence(service_cmd_len, Encoding.UTF8).ToString();
            }
            else
            {
                SSOReq = Buf.ReadUnsignedInt().ToString();
                Buf.ReadByte();
                int qq_len = Buf.ReadInt() - 4;
                Uin = Buf.ReadCharSequence(qq_len, Encoding.UTF8).ToString();
                byte[] remaining = Util.ReadRemainingBytes(Buf);
                byte[] decrypt_data = Tea.Decrypt(remaining, new byte[16]);
                if (decrypt_data == null) return;
                var buf_part1 = Unpooled.WrappedBuffer(decrypt_data);
                buf_part1.ReadInt();
                int service_cmd_len = buf_part1.ReadInt() - 4;
                ServiceCmd = buf_part1.ReadCharSequence(service_cmd_len, Encoding.UTF8).ToString();
            }
        }

        protected void Resolve0B00()
        {
            throw new NotImplementedException();
        }

        public override string ToString()
        {
            return $"Orientation={Orientation}, ServiceCmd={ServiceCmd}, SSOReq={SSOReq}";
        }
    }
}
