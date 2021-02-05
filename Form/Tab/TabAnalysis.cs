/*
 *  Copyright 2021-2021 yggo Technologies and contributors.
 *
 *  此源代码的使用受 GNU AFFERO GENERAL PUBLIC LICENSE version 3 许可证的约束, 可以在以下链接找到该许可证.
 *  Use of this source code is governed by the GNU AGPLv3 license that can be found through the following link.
 *
 *  https://github.com/yggo/androidqq-sniffer/blob/main/LICENSE
 */

using System;
using System.Windows.Forms;
using YgAndroidQQSniffer.Component;

namespace YgAndroidQQSniffer.Tab
{
    [Attributes.CustomEvent(nameof(TabAnalysis))]
    public class TabAnalysis : ICustomControlEvents
    {
        private static FormMain Frm => FormMain.Form;

        public void Register()
        {
            Frm.copy_payload.Click += CopyPayload_Click;
            Frm.clear_analysis_listview.Click += ClearAnalysisListView_Click;
        }

        #region ctx_menu_trace_flow

        private void CopyPayload_Click(object sender, EventArgs e)
        {
            if (Frm.lv_analysis_log.SelectedItems.Count == 1)
            {
                if (Frm.lv_analysis_log.SelectedItems[0].Tag is PacketAnalyzer pkg)
                {
                    Clipboard.SetText(pkg.HexPayload);
                }
            }
        }

        private void ClearAnalysisListView_Click(object sender, EventArgs e)
        {
            Frm.lv_analysis_log.Items.Clear();
        }
        #endregion
    }
}
