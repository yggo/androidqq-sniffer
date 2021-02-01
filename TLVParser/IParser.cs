using DotNetty.Buffers;

namespace YgAndroidQQSniffer.TLVParser
{
    public interface IParser
    {
        string Parse(IByteBuffer value);
    }
}
