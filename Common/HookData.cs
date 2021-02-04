namespace YgAndroidQQSniffer
{
    public static class HookData
    {
        private static FormMain Frm => FormMain.Form;

        #region Hook Data
        public static string _androidId = string.Empty;
        public static string AndroidId { get => _androidId; set { if (_androidId == value) return; _androidId = value; Frm.ThreadSafeUpdate(() => Frm.txt_tool_hookdata_androidId.Text = _androidId); } }

        public static string _mac = string.Empty;
        public static string Mac { get => _mac; set { if (_mac == value) return; _mac = value; Frm.ThreadSafeUpdate(() => Frm.txt_tool_hookdata_mac.Text = _mac); } }

        public static string _imsi = string.Empty;
        public static string IMSI { get => _imsi; set { if (_imsi == value) return; _imsi = value; Frm.ThreadSafeUpdate(() => Frm.txt_tool_hookdata_imsi.Text = _imsi); } }

        public static string _imei = string.Empty;
        public static string IMEI { get => _imei; set { if (_imei == value) return; _imei = value; Frm.ThreadSafeUpdate(() => Frm.txt_tool_hookdata_imei.Text = _imei); } }

        public static string _bssid = string.Empty;
        public static string BSSID { get => _bssid; set { if (_bssid == value) return; _bssid = value; Frm.ThreadSafeUpdate(() => Frm.txt_tool_hookdata_bssid.Text = _bssid); } }

        public static string _d2key = string.Empty;
        public static string D2KEY { get => _d2key; set { if (_d2key == value) return; _d2key = value; Frm.ThreadSafeUpdate(() => Frm.txt_tool_hookdata_d2key.Text = _d2key); } }

        public static string _a1 = string.Empty;
        public static string A1 { get => _a1; set { if (_a1 == value) return; _a1 = value; Frm.ThreadSafeUpdate(() => Frm.txt_tool_hookdata_A1.Text = _a1); } }

        public static string _a2 = string.Empty;
        public static string A2 { get => _a2; set { if (_a2 == value) return; _a2 = value; Frm.ThreadSafeUpdate(() => Frm.txt_tool_hookdata_A2.Text = _a2); } }

        public static string _a3 = string.Empty;
        public static string A3 { get => _a3; set { if (_a3 == value) return; _a3 = value; Frm.ThreadSafeUpdate(() => Frm.txt_tool_hookdata_A3.Text = _a3); } }

        public static string _tgtkey = string.Empty;
        public static string TGTKEY { get => _tgtkey; set { if (_tgtkey == value) return; _tgtkey = value; Frm.ThreadSafeUpdate(() => Frm.txt_tool_hookdata_tgtkey.Text = _tgtkey); } }

        public static string _nick = string.Empty;
        public static string Nick { get => _nick; set { if (_nick == value) return; _nick = value; Frm.ThreadSafeUpdate(() => Frm.txt_tool_hookdata_nick.Text = _nick); } }

        public static string _uin = string.Empty;
        public static string Uin { get => _uin; set { if (_uin == value) return; _uin = value; Frm.ThreadSafeUpdate(() => Frm.txt_tool_hookdata_uin.Text = _uin); } }

        public static string _pwd = string.Empty;
        public static string Pwd { get => _pwd; set { if (_pwd == value) return; _pwd = value; Frm.ThreadSafeUpdate(() => Frm.txt_tool_hookdata_pwd.Text = _pwd); } }

        #endregion
    }
}
