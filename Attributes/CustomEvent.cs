using System;

namespace YgAndroidQQSniffer.Attributes
{
    [AttributeUsage(AttributeTargets.Class, AllowMultiple = false, Inherited = false)]
    public class CustomEvent : Attribute
    {
        private readonly string windowName;

        public string WindowName => windowName;

        public CustomEvent(string windowName)
        {
            this.windowName = windowName;
        }
    }
}
