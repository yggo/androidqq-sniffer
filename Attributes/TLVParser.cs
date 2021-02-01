using System;

namespace YgAndroidQQSniffer.Attributes
{
    [AttributeUsage(AttributeTargets.Class, AllowMultiple = false, Inherited = false)]
    public class TLVParser : Attribute
    {
        private readonly short cmd;

        public short Cmd { get { return cmd; } }
        public TLVParser(short cmd)
        {
            this.cmd = cmd;
        }
    }
}
