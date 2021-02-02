using System;
using System.Runtime.InteropServices;

namespace YgAndroidQQSniffer.Utils
{
    public class EcdhCrypt
    {
        internal static class Libcrypto
        {
            private const string DllName = "Libs\\libcrypto.dll";

            [DllImport(DllName, EntryPoint = "EC_KEY_new_by_curve_name")]
            public static extern IntPtr EC_KEY_new_by_curve_name(int nid);

            [DllImport(DllName, EntryPoint = "EC_KEY_generate_key")]
            public static extern IntPtr EC_KEY_generate_key(IntPtr key);

            [DllImport(DllName, EntryPoint = "EC_KEY_get0_group")]
            public static extern IntPtr EC_KEY_get0_group(IntPtr key);

            [DllImport(DllName, EntryPoint = "EC_KEY_get0_public_key")]
            public static extern IntPtr EC_KEY_get0_public_key(IntPtr key);

            [DllImport(DllName, EntryPoint = "EC_POINT_point2oct")]
            public static extern int EC_POINT_point2oct(IntPtr group, IntPtr point, int form, byte[] pubkey, int ECDH_SIZE, int ctx);

            [DllImport(DllName, EntryPoint = "EC_KEY_get0_private_key")]
            public static extern IntPtr EC_KEY_get0_private_key(IntPtr key);

            [DllImport(DllName, EntryPoint = "BN_bn2mpi")]
            public static extern int BN_bn2mpi(IntPtr pribignum, byte[] pout);

            [DllImport(DllName, EntryPoint = "BN_new")]
            public static extern IntPtr BN_new();

            [DllImport(DllName, EntryPoint = "BN_mpi2bn")]
            public static extern int BN_mpi2bn(byte[] key, int len, IntPtr bn);

            [DllImport(DllName, EntryPoint = "EC_KEY_set_private_key")]
            public static extern int EC_KEY_set_private_key(IntPtr ec_key, IntPtr bn);

            [DllImport(DllName, EntryPoint = "BN_free")]
            public static extern int BN_free(IntPtr bn);

            [DllImport(DllName, EntryPoint = "EC_POINT_new")]
            public static extern IntPtr EC_POINT_new(IntPtr ec_group);

            [DllImport(DllName, EntryPoint = "EC_POINT_oct2point")]
            public static extern int EC_POINT_oct2point(IntPtr ec_group, IntPtr ec_point, byte[] pubkey, int ECDH_SIZE, int ctx);

            [DllImport(DllName, EntryPoint = "ECDH_compute_key")]
            public static extern int ECDH_compute_key(byte[] @out, int out_len, IntPtr pub_key, IntPtr ecdh, int kdf);
        }

        private byte[] PublicKey = new byte[1024];
        private byte[] PrivateKey = new byte[1024];
        private readonly byte[] ShareKey = new byte[16];
        private const string SvrPubKey = "0440eaf325b9c66225143aa7f3961c953c3d5a8048c2b73293cdc7dcbab7f35c4c66aa8917a8fd511f9d969d02c8501bcaa3e3b11746f00567e3aea303ac5f2d25";
        public int Publen { get; private set; }
        public int Prilen { get; private set; }

        public void GenEcdhKeys()
        {
            IntPtr ec_key = Libcrypto.EC_KEY_new_by_curve_name(415);
            Libcrypto.EC_KEY_generate_key(ec_key);

            IntPtr ec_group = Libcrypto.EC_KEY_get0_group(ec_key);
            IntPtr ec_point = Libcrypto.EC_KEY_get0_public_key(ec_key);

            Publen = Libcrypto.EC_POINT_point2oct(ec_group, ec_point, 4, PublicKey, 65, 0);
            ec_point = Libcrypto.EC_KEY_get0_private_key(ec_key);
            Prilen = Libcrypto.BN_bn2mpi(ec_point, PrivateKey);
        }

        public byte[] GetPublicKeyByte()
        {
            Array.Resize(ref PublicKey, Publen);
            return PublicKey;
        }

        public byte[] GetPrivateKeyByte()
        {
            Array.Resize(ref PrivateKey, Prilen);
            return PrivateKey;
        }

        public string GetPublicKeyHex()
        {
            return GetPublicKeyByte().ToHex();
        }

        public string GetPrivateKeyHex()
        {
            return GetPrivateKeyByte().ToHex();
        }

        private byte[] GenShareKeyByte(byte[] publicKey, byte[] privateKey)
        {
            IntPtr ec_key = Libcrypto.EC_KEY_new_by_curve_name(415);
            IntPtr bn = Libcrypto.BN_new();
            Libcrypto.BN_mpi2bn(privateKey, privateKey.Length, bn);
            Libcrypto.EC_KEY_set_private_key(ec_key, bn);
            Libcrypto.BN_free(bn);

            IntPtr ec_group = Libcrypto.EC_KEY_get0_group(ec_key);
            IntPtr ec_point = Libcrypto.EC_POINT_new(ec_group);
            Libcrypto.EC_POINT_oct2point(ec_group, ec_point, publicKey, publicKey.Length, 0);
            Libcrypto.ECDH_compute_key(ShareKey, 16, ec_point, ec_key, 0);
            return ShareKey;
        }

        public string GenShareKeyHex(byte[] privateKey)
        {
            return GenShareKeyByte(SvrPubKey.ToBytes(), privateKey).Md5().ToHex();
        }

        public string GenShareKeyHex(byte[] publicKey, byte[] privateKey)
        {
            return GenShareKeyByte(publicKey, privateKey).Md5().ToHex();
        }

        public override string ToString()
        {
            return string.Format("Pubkey({0}): {1}\nPrikey({2}): {3}\nShakey({4}): {5}",
                Publen, GetPublicKeyHex(), Prilen, GetPrivateKeyHex(), ShareKey.Length, ShareKey.ToHex());
        }
    }
}
