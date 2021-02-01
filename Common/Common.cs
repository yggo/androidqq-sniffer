using App.Metrics.Concurrency;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using YgAndroidQQSniffer.Extension;

namespace YgAndroidQQSniffer
{
    public enum KeyType
    {
        [Display(Description = "share_key")]
        SHARE_KEY,

        [Display(Description = "zero_key")]
        ZERO_KEY,

        [Display(Description = "d2_key")]
        D2_KEY,

        [Display(Description = "rand_tgt_key")]
        RAND_TGT_KEY,

        [Display(Description = "custom_key")]
        CUSTOM_KEY,

        [Display(Description = "cached_key")]
        CACHED_SHAKEY,
    }
    public class DecryptionKey
    {
        public string Key { get; set; }
        public KeyType KeyType { get; set; }
        public string PrivateKey { get; set; }
        public string PublicKey { get; set; }
    }
    public class Common
    {
        public static AtomicInteger Index;

        public static LinkedList<DecryptionKey> Keys { get; set; } = new LinkedList<DecryptionKey>();

        static Common()
        {
            Keys.AddLast(new DecryptionKey() { Key = new byte[16].HexDump(), KeyType = KeyType.ZERO_KEY });
        }

        public static byte[] TeaKeyLogDecrypt(byte[] In, out DecryptionKey decryptionKey)
        {
            decryptionKey = null;
            List<DecryptionKey> keys = Keys.ToList();
            for (int i = 0; i < keys.Count; i++)
            {
                var d = Tea.Decrypt(In, HexUtil.DecodeHex(keys[i].Key));
                if (d != null)
                {
                    decryptionKey = keys[i];
                    return d;
                }
            }
            return null;
        }

        public static string PrettyKeyDecryptDump(byte[] decrypt_data, DecryptionKey decryption_key)
        {
            string decryption_key_str = $"{decryption_key.Key} keyType={decryption_key.KeyType.GetDisplayDescription()}";
            if (decryption_key.KeyType == KeyType.SHARE_KEY)
            {
                decryption_key_str += $" prikey={decryption_key.PrivateKey}";
                decryption_key_str += $" pubkey={decryption_key.PublicKey}";
            }
            return $"\n\n[key={decryption_key_str}\n{decrypt_data.HexDump()}]\n\n";
        }

        public static List<DecryptionKey> GetTeaKeyLogSetList()
        {
            List<DecryptionKey> decryptionKeys = new List<DecryptionKey>();
            Keys.ToList().ForEach(k =>
            {
                if (decryptionKeys.Find(d => d.Key == k.Key) == null) decryptionKeys.Add(k);
            });
            return decryptionKeys;
        }
    }
}
