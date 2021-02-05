/*
 *  Copyright 2021-2021 yggo Technologies and contributors.
 *
 *  此源代码的使用受 GNU AFFERO GENERAL PUBLIC LICENSE version 3 许可证的约束, 可以在以下链接找到该许可证.
 *  Use of this source code is governed by the GNU AGPLv3 license that can be found through the following link.
 *
 *  https://github.com/yggo/androidqq-sniffer/blob/main/LICENSE
 */

using System;
using YgAndroidQQSniffer.Utils;

namespace YgAndroidQQSniffer.Tab
{
    [Attributes.CustomEvent(nameof(TabECDH))]
    public class TabECDH : ICustomControlEvents
    {
        private static FormMain Frm => FormMain.Form;

        public void Register()
        {
            Frm.btnClientGenKeys.Click += BtnClientGenKeys_Click;
            Frm.btnServerGenKeys.Click += BtnServerGenKeys_Click;
            Frm.btnExchangePubkey.Click += BtnExchangePubkey_Click;
            Frm.btnClientGenShakey.Click += BtnClientGenShakey_Click;
            Frm.btnServerGenShakey.Click += BtnServerGenShakey_Click;
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
