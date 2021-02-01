using System;
using YgAndroidQQSniffer.Utils;

namespace YgAndroidQQSniffer.Tab
{
    [Attributes.CustomEvent(nameof(TabECDH))]
    public class TabECDH : ICustomControlEvents
    {
        private static FormMain Frm { get => FormMain.Form; }
        public void Register()
        {
            Frm.btnClientGenKeys.Click += new EventHandler(BtnClientGenKeys_Click);
            Frm.btnServerGenKeys.Click += new EventHandler(BtnServerGenKeys_Click);
            Frm.btnExchangePubkey.Click += new EventHandler(BtnExchangePubkey_Click);
            Frm.btnClientGenShakey.Click += new EventHandler(BtnClientGenShakey_Click);
            Frm.btnServerGenShakey.Click += new EventHandler(BtnServerGenShakey_Click);
        }

        private void BtnClientGenKeys_Click(object sender, EventArgs e)
        {
            EcdhCrypt ecdh = new EcdhCrypt();
            ecdh.GenEcdhKeys();
            Frm.txtClientPubkey.Text = ecdh.GetPublicKeyHex();
            Frm.txtClientPrikey.Text = ecdh.GetPrivateKeyHex();
        }

        private void BtnServerGenKeys_Click(object sender, EventArgs e)
        {
            EcdhCrypt ecdh = new EcdhCrypt();
            ecdh.GenEcdhKeys();
            Frm.txtServerPubkey.Text = ecdh.GetPublicKeyHex();
            Frm.txtServerPrikey.Text = ecdh.GetPrivateKeyHex();
        }

        private void BtnExchangePubkey_Click(object sender, EventArgs e)
        {
            string clientPubkey = Frm.txtClientPubkey.Text;
            Frm.txtClientPubkey.Text = Frm.txtServerPubkey.Text;
            Frm.txtServerPubkey.Text = clientPubkey;
        }

        private void BtnClientGenShakey_Click(object sender, EventArgs e)
        {
            EcdhCrypt ecdh = new EcdhCrypt();
            Frm.txtClientShakey.Text = ecdh.GenShareKeyHex(Frm.txtClientPubkey.Text.ToBytes(), Frm.txtClientPrikey.Text.ToBytes());
        }

        private void BtnServerGenShakey_Click(object sender, EventArgs e)
        {
            EcdhCrypt ecdh = new EcdhCrypt();
            Frm.txtServerShakey.Text = ecdh.GenShareKeyHex(Frm.txtServerPubkey.Text.ToBytes(), Frm.txtServerPrikey.Text.ToBytes());
        }
    }
}
