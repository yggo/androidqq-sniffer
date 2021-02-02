using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using YgAndroidQQSniffer.Component;
using YgAndroidQQSniffer.Extension;

namespace YgAndroidQQSniffer.Tab.TabCapture
{
    [Attributes.CustomEvent(nameof(TabCapture))]
    public partial class TabCapture : ICustomControlEvents
    {
        private static FormMain Frm { get => FormMain.Form; }

        public void Register()
        {
            
        }
        
    }
}
