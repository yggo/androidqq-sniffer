using DotNetty.Buffers;
using System;
using System.Text;
using YgAndroidQQSniffer.TLVParser;

namespace YgAndroidQQSniffer.Component
{
    public class PacketFormatter : IParser
    {
        private StringBuilder _sb { get; set; } = new StringBuilder();
        private IByteBuffer _buf { get; set; }
        public string Uin { get; set; }
        public string Parse(IByteBuffer value)
        {
            _buf = value;
            ReadPacketLen();
            int packet_type = _buf.ReadInt();
            byte encrypt_type = _buf.ReadByte();
           
            if (packet_type == 0x0A)
            {
                _sb.Append(packet_type.HexPadLeft().HexDump()).Append(" //packet_type").AppendLine();
                if (encrypt_type == 0x01)
                {
                    _sb.Append(encrypt_type.HexPadLeft().HexDump()).Append(" //encrypt_type").AppendLine();
                    Resolve0A01();
                }
                else if (encrypt_type == 0x02)
                {
                    _sb.Append(encrypt_type.HexPadLeft().HexDump()).Append(" //encrypt_type").AppendLine();
                    Resolve0A02();
                }
                else if (encrypt_type == 0x00)
                {
                    _sb.Append(encrypt_type.HexPadLeft().HexDump()).Append(" //encrypt_type").AppendLine();
                    Resolve0A00();
                }
                else
                {
                    throw new InvalidOperationException("invalid encrypt_type: " + encrypt_type.HexPadLeft());
                }
            }
            else if (packet_type == 0x0B)
            {
                _sb.Append(packet_type.HexPadLeft().HexDump()).Append(" //packet_type").AppendLine();
                if (encrypt_type == 0x01)
                {
                    _sb.Append(encrypt_type.HexPadLeft().HexDump()).Append(" //encrypt_type").AppendLine();
                    Resolve0B01();
                }
                else if (encrypt_type == 0x02)
                {
                    _sb.Append(encrypt_type.HexPadLeft().HexDump()).Append(" //encrypt_type").AppendLine();
                    Resolve0B02();
                }
                else if (encrypt_type == 0x00)
                {
                    _sb.Append(encrypt_type.HexPadLeft().HexDump()).Append(" //encrypt_type").AppendLine();
                    Resolve0B00();
                }
                else
                {
                    throw new InvalidOperationException("invalid encrypt_type: " + encrypt_type.HexPadLeft());
                }
            }
            else
            {
                throw new InvalidOperationException("invalid packet_type: " + packet_type.HexPadLeft());
            }
            return _sb.ToString();
        }
 
        private void ReadPacketLen()
        {
            int packet_len = _buf.ReadInt();
            _sb.Append(packet_len.HexPadLeft().HexDump()).Append($" //packet_len {packet_len}").AppendLine();
        }

        private void Resolve0A01()
        {
            throw new NotImplementedException();
        }

        private void Resolve0A02()
        {
            if (_buf.GetInt(_buf.ReaderIndex) == 0x04)
            {
                _sb.Append(_buf.ReadInt().HexPadLeft().HexDump()).AppendLine();
            }
            _sb.Append(_buf.ReadByte().HexPadLeft().HexDump()).AppendLine();

            int uin_len = _buf.ReadInt() - 4;
            Uin = _buf.ReadCharSequence(uin_len, Encoding.UTF8).ToString();

            _sb.Append((uin_len + 4).HexPadLeft().HexDump()).Append(" //uin_len").AppendLine();
            _sb.Append(Encoding.UTF8.GetBytes(Uin).HexDump()).Append($" //uin {Uin}").AppendLine();

            byte[] remaining = Util.ReadRemainingBytes(_buf);
            _sb.Append(remaining.HexDump()).AppendLine().AppendLine();

            byte[] decrypt_data = Common.TeaKeyLogDecrypt(remaining, out DecryptionKey decryptionKey);
            if (decrypt_data == null) return;

            var buf_part1 = Unpooled.WrappedBuffer(decrypt_data);
            _sb.Append(Common.PrettyKeyDecryptDump(decrypt_data, decryptionKey)).AppendLine();
            int head_size = buf_part1.ReadInt();
            _sb.Append(head_size.HexPadLeft().HexDump()).Append($" //head_size {head_size}").AppendLine();

            uint sso_seq = buf_part1.ReadUnsignedInt();
            _sb.Append(sso_seq.HexPadLeft().HexDump()).Append($" //sso_seq {sso_seq}").AppendLine();

            if (buf_part1.GetInt(buf_part1.ReaderIndex) == 0x00)
            {
                _sb.Append(buf_part1.ReadInt().HexPadLeft().HexDump()).AppendLine();
                _sb.Append(buf_part1.ReadInt().HexPadLeft().HexDump()).AppendLine();
            }
            else
            {
                uint appid = buf_part1.ReadUnsignedInt();
                _sb.Append(appid.HexPadLeft().HexDump()).Append($" //appid {appid}").AppendLine();

                uint appid2 = buf_part1.ReadUnsignedInt();
                _sb.Append(appid2.HexPadLeft().HexDump()).Append($" //appid2 {appid2}").AppendLine();

                _sb.Append(buf_part1.ReadBytes(12).HexDump()).AppendLine();

                if (buf_part1.GetInt(buf_part1.ReaderIndex) == 0x4C)
                {
                    int tgt_len = buf_part1.ReadInt();
                    _sb.Append(tgt_len.HexPadLeft().HexDump()).Append($"// tgt_len {tgt_len}").AppendLine();
                    _sb.Append(buf_part1.ReadBytes(tgt_len - 4).HexDump()).Append(" //tgt").AppendLine();
                }
                else
                {
                    _sb.Append(buf_part1.ReadInt().HexPadLeft().HexDump()).AppendLine();
                }
            }

            int service_cmd_len = buf_part1.ReadInt() - 4;
            string serviceCmd = buf_part1.ReadCharSequence(service_cmd_len, Encoding.UTF8).ToString();
            _sb.Append((service_cmd_len + 4).HexPadLeft().HexDump()).Append($" //service_cmd_len {service_cmd_len}").AppendLine();
            _sb.Append(Encoding.UTF8.GetBytes(serviceCmd).HexDump()).Append($" //serviceCmd [{serviceCmd}]").AppendLine();

            _sb.Append(buf_part1.ReadInt().HexPadLeft().HexDump()).AppendLine();

            int imei_len = buf_part1.ReadInt() - 4;
            string imei = buf_part1.ReadCharSequence(imei_len, Encoding.UTF8).ToString();
            _sb.Append((imei_len + 4).HexPadLeft().HexDump()).Append($" //imei_len {imei_len}").AppendLine();
            _sb.Append(Encoding.UTF8.GetBytes(imei).HexDump()).Append($" //imei [{imei}]").AppendLine();

            if (buf_part1.GetInt(buf_part1.ReaderIndex) == 0x14)
            {
                _sb.Append(buf_part1.ReadInt().HexPadLeft().HexDump()).AppendLine();
                _sb.Append(buf_part1.ReadBytes(16).HexDump()).AppendLine();
            }
            else
            {
                _sb.Append(buf_part1.ReadInt().HexPadLeft().HexDump()).AppendLine();
            }

            short ksid_len = buf_part1.ReadShort();
            string ksid = buf_part1.ReadCharSequence(ksid_len - 2, Encoding.UTF8).ToString();
            _sb.Append((ksid_len + 4).HexPadLeft().HexDump()).Append($" //ksid_len {ksid_len}").AppendLine();
            _sb.Append(Encoding.UTF8.GetBytes(ksid).HexDump()).Append($" //ksid [{ksid}]").AppendLine();

            _sb.Append(buf_part1.ReadInt().HexPadLeft().HexDump()).AppendLine();

            uint wupBuffer_len = buf_part1.ReadUnsignedInt();
            _sb.Append((wupBuffer_len + 4).HexPadLeft().HexDump()).Append($" //wupBuffer_len {wupBuffer_len}").AppendLine();

            _sb.Append(buf_part1.HexDump());
        }

        private void Resolve0A00()
        {

        }

        private void Resolve0B01()
        {

        }

        private void Resolve0B02()
        {

        }

        private void Resolve0B00()
        {

        }
    }
}
