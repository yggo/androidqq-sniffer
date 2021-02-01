using NLog;
using System;

namespace YgAndroidQQSniffer
{
    /// <summary>
    /// 加密解密QQ消息的工具类. QQ消息的加密算法是一个16次的迭代过程，并且是反馈的，每一个加密单元是8字节，输出也是8字节，密钥是16字节
    /// 我们以prePlain表示前一个明文块，plain表示当前明文块，crypt表示当前明文块加密得到的密文块，preCrypt表示前一个密文块
    /// f表示加密算法，d表示解密算法 那么从plain得到crypt的过程是: crypt = f(plain &circ; preCrypt) &circ;
    /// prePlain 所以，从crypt得到plain的过程自然是 plain = d(crypt &circ; prePlain) &circ;
    /// preCrypt 此外，算法有它的填充机制，其会在明文前和明文后分别填充一定的字节数，以保证明文长度是8字节的倍数
    /// 填充的字节数与原始明文长度有关，填充的方法是:
    /// 
    /// <code>
    /// 
    /// ------- 消息填充算法 ----------- 
    /// a = (明文长度 + 10) mod 8
    /// if(a 不等于 0) a = 8 - a;
    /// b = 随机数 &amp; 0xF8 | a;              这个的作用是把a的值保存了下来
    /// plain[0] = b;                       然后把b做为明文的第0个字节，这样第0个字节就保存了a的信息，这个信息在解密时就要用来找到真正明文的起始位置
    /// plain[1 至 a+2] = 随机数 &amp; 0xFF;    这里用随机数填充明文的第1到第a+2个字节
    /// plain[a+3 至 a+3+明文长度-1] = 明文; 从a+3字节开始才是真正的明文
    /// plain[a+3+明文长度, 最后] = 0;       在最后，填充0，填充到总长度为8的整数为止。到此为止，结束了，这就是最后得到的要加密的明文内容
    /// ------- 消息填充算法 ------------
    /// 
    /// </code>
    /// 
    /// </summary>
    /// <author>
    /// 
    /// </author>
    /// <author>
    /// 
    /// </author>
    /// <author>
    /// overred
    /// </author>

    public struct Tea
    {
        public static Logger Logger { get; set; } = LogManager.GetCurrentClassLogger();
        ///<summary>
        ///指向当前的明文块
        ///</summary>
        private byte[] plain;
        ///<summary>
        /// 这指向前面一个明文块
        ///</summary>
        private byte[] prePlain;
        ///<summary>
        /// 输出的密文或者明文
        ///</summary>
        private byte[] output;
        ///<summary>
        /// 当前加密的密文位置和上一次加密的密文块位置，他们相差8
        ///</summary>
        private int crypt, preCrypt;
        ///<summary>
        /// 当前处理的加密解密块的位置
        ///</summary>
        private int pos;
        ///<summary>
        /// 填充数
        ///</summary>
        private int padding;
        ///<summary>
        /// 密钥
        ///</summary>
        private byte[] key;
        ///<summary>
        /// 用于加密时，表示当前是否是第一个8字节块，因为加密算法是反馈的
        ///     但是最开始的8个字节没有反馈可用，所有需要标明这种情况
        ///</summary>
        private bool header;
        ///<summary>
        /// 这个表示当前解密开始的位置，之所以要这么一个变量是为了避免当解密到最后时
        ///     后面已经没有数据，这时候就会出错，这个变量就是用来判断这种情况免得出错
        ///</summary>
        private int contextStart;

        /// <summary>
        /// 随机类
        /// </summary>
        private static Random random_Renamed_Field;

        ///<summary>
        /// 随机数对象
        ///</summary>
        private static Random random;

        ///<summary>
        /// 随机数对象
        ///</summary>
        public static Random xRandom
        {
            get
            {
                if (random_Renamed_Field == null)
                    random_Renamed_Field = new Random();
                return random_Renamed_Field;
            }
        }


        public static byte[] ToBytes(uint a, uint b)
        {
            byte[] bytes = new byte[8];
            bytes[0] = (byte)(a >> 24);
            bytes[1] = (byte)(a >> 16);
            bytes[2] = (byte)(a >> 8);
            bytes[3] = (byte)a;
            bytes[4] = (byte)(b >> 24);
            bytes[5] = (byte)(b >> 16);
            bytes[6] = (byte)(b >> 8);
            bytes[7] = (byte)b;
            return bytes;
        }


        /// <summary>
        /// 把字节数组从offset开始的len个字节转换成一个unsigned int， 因为C#里面有unsigned，所以unsigned
        /// int使用uint表示的。如果len大于4，则认为len等于4。如果len小于4，则高位填0 <br>
        /// (edited by ) 改变了算法, 性能稍微好一点. 在我的机器上测试10000次, 原始算法花费18s, 这个算法花费12s.
        /// </summary>
        /// <param name="input">
        /// 字节数组.
        /// </param>
        /// <param name="offset">
        /// 从哪里开始转换.
        /// </param>
        /// <param name="len">
        /// 转换长度, 如果len超过8则忽略后面的
        /// </param>
        /// <returns>
        /// </returns>
        public static uint GetUInt(byte[] input, int offset, int len)
        {
            uint ret = 0;
            int end = (len > 4) ? (offset + 4) : (offset + len);
            for (int i = offset; i < end; i++)
            {
                ret <<= 8;
                ret |= input[i];
            }
            return ret;
        }

        /// <param name="input">需要被解密的密文</param>
        /// <param name="key">密钥</param>
        /// <returns> Message 已解密的消息</returns>
        public static byte[] Decrypt(byte[] input, byte[] key)
        {
            Tea crypter = new Tea();
            crypter.header = true;
            return crypter.Decrypt0(input, key);
        }

        /// <param name="input">需要被解密的密文</param>
        /// <param name="key">密钥</param>
        /// <returns> Message 已解密的消息</returns>
        public static byte[] Decrypt(byte[] input, int offset, int len, byte[] key)
        {
            Tea crypter = new Tea();
            crypter.header = true;
            return crypter.Decrypt0(input, offset, len, key);
        }

        /// <param name="input">需要加密的明文</param>
        /// <param name="key">密钥</param>
        /// <returns> Message 密文</returns>
        public static byte[] Encrypt(byte[] input, byte[] key)
        {
            Tea crypter = new Tea();
            crypter.header = true;
            return crypter.Encrypt0(input, key);
        }

        /// <param name="input">需要加密的明文</param>
        /// <param name="key">密钥</param>
        /// <returns>Message 密文</returns>
        public static byte[] Encrypt(byte[] input, int offset, int len, byte[] key)
        {
            Tea crypter = new Tea();
            crypter.header = true;
            return crypter.Encrypt0(input, offset, len, key);
        }

        /// <summary>
        /// 抛出异常。
        /// </summary>
        /// <param name="message">异常信息</param>
        private static void throwException(string message)
        {
            throw new CrypterException(message);
        }

        /// <summary> 解密</summary>
        /// <param name="input">
        /// 密文
        /// </param>
        /// <param name="offset">
        /// 密文开始的位置
        /// </param>
        /// <param name="len">
        /// 密文长度
        /// </param>
        /// <param name="key">
        /// 密钥
        /// </param>
        /// <returns> 明文
        /// </returns>
        public byte[] Decrypt0(byte[] input, int offset, int len, byte[] key)
        {
            crypt = preCrypt = 0;
            this.key = key;
            int count;
            byte[] m = new byte[offset + 8];

            // 因为QQ消息加密之后至少是16字节，并且肯定是8的倍数，这里检查这种情况
            if ((len % 8 != 0) || (len < 16)) return null;
            //throwException(@"len is not correct.");
            // 得到消息的头部，关键是得到真正明文开始的位置，这个信息存在第一个字节里面，所以其用解密得到的第一个字节与7做与
            prePlain = Decipher(input, offset);
            pos = prePlain[0] & 0x7;
            // 得到真正明文的长度
            count = len - pos - 10;
            // 如果明文长度小于0，那肯定是出错了，比如传输错误之类的，返回
            if (count < 0) return null;
            //throwException(@"count is not correct");

            // 这个是临时的preCrypt，和加密时第一个8字节块没有prePlain一样，解密时
            //     第一个8字节块也没有preCrypt，所有这里建一个全0的
            for (int i = offset; i < m.Length; i++)
                m[i] = 0;
            // 通过了上面的代码，密文应该是没有问题了，我们分配输出缓冲区
            output = new byte[count];
            // 设置preCrypt的位置等于0，注意目前的preCrypt位置是指向m的，因为java没有指针，所以我们在后面要控制当前密文buf的引用
            preCrypt = 0;
            // 当前的密文位置，为什么是8不是0呢？注意前面我们已经解密了头部信息了，现在当然该8了
            crypt = 8;
            // 自然这个也是8
            contextStart = 8;
            // 加1，和加密算法是对应的
            pos++;

            // 开始跳过头部，如果在这个过程中满了8字节，则解密下一块
            // 因为是解密下一块，所以我们有一个语句 m = in，下一块当然有preCrypt了，我们不再用m了
            // 但是如果不满8，这说明了什么？说明了头8个字节的密文是包含了明文信息的，当然还是要用m把明文弄出来
            // 所以，很显然，满了8的话，说明了头8个字节的密文除了一个长度信息有用之外，其他都是无用的填充
            padding = 1;
            while (padding <= 2)
            {
                if (pos < 8)
                {
                    pos++;
                    padding++;
                }
                if (pos == 8)
                {
                    m = input;
                    if (!Decrypt8Bytes(input, offset, len)) return null;
                    //throwException(@"Decrypt8Bytes() failed.");
                }
            }

            // 这里是解密的重要阶段，这个时候头部的填充都已经跳过了，开始解密
            // 注意如果上面一个while没有满8，这里第一个if里面用的就是原始的m，否则这个m就是in了
            int i2 = 0;
            while (count != 0)
            {
                if (pos < 8)
                {
                    output[i2] = (byte)(m[offset + preCrypt + pos] ^ prePlain[pos]);
                    i2++;
                    count--;
                    pos++;
                }
                if (pos == 8)
                {
                    m = input;
                    preCrypt = crypt - 8;
                    if (!Decrypt8Bytes(input, offset, len)) return null;
                    //throwException(@"Decrypt8Bytes() failed.");
                }
            }

            // 最后的解密部分，上面一个while已经把明文都解出来了，到了这里还剩下什么？对了，还剩下尾部的填充，应该全是0
            // 所以这里有检查是否解密了之后是0，如果不是的话那肯定出错了，所以返回null
            for (padding = 1; padding < 8; padding++)
            {
                if (pos < 8)
                {
                    if ((m[offset + preCrypt + pos] ^ prePlain[pos]) != 0) return null;
                    //throwException(@"tail is not filled correct.");
                    pos++;
                }
                if (pos == 8)
                {
                    m = input;
                    preCrypt = crypt;
                    if (!Decrypt8Bytes(input, offset, len)) return null;
                    //throwException(@"Decrypt8Bytes() failed.");
                }
            }
            return output;
        }

        /// <param name="input">
        /// 需要被解密的密文
        /// </param>
        /// <param name="key">
        /// 密钥
        /// </param>
        /// <returns> Message 已解密的消息
        /// </returns>
        public byte[] Decrypt0(byte[] input, byte[] key)
        {
            return Decrypt(input, 0, input.Length, key);
        }

        /// <summary>加密</summary>
        /// <param name="input">明文字节数组
        /// </param>
        /// <param name="offset">开始加密的偏移
        /// </param>
        /// <param name="len">加密长度
        /// </param>
        /// <param name="key">密钥
        /// </param>
        /// <returns> 密文字节数组
        /// </returns>
        public byte[] Encrypt0(byte[] input, int offset, int len, byte[] key)
        {
            plain = new byte[8];
            prePlain = new byte[8];
            pos = 1;
            padding = 0;
            crypt = preCrypt = 0;
            this.key = key;
            header = true;

            // 计算头部填充字节数
            pos = (len + 0x0A) % 8;
            if (pos != 0)
                pos = 8 - pos;
            // 计算输出的密文长度
            output = new byte[len + pos + 10];
            // 这里的操作把pos存到了plain的第一个字节里面
            //     0xF8后面三位是空的，正好留给pos，因为pos是0到7的值，表示文本开始的字节位置
            int t1 = 0x7648354F;

            plain[0] = (byte)((t1 & 0xF8) | pos);

            // 这里用随机产生的数填充plain[1]到plain[pos]之间的内容
            for (int i = 1; i <= pos; i++)
                plain[i] = (byte)(t1 & 0xFF);
            pos++;
            // 这个就是prePlain，第一个8字节块当然没有prePlain，所以我们做一个全0的给第一个8字节块
            for (int i = 0; i < 8; i++)
                prePlain[i] = (byte)(0x0);

            // 继续填充2个字节的随机数，这个过程中如果满了8字节就加密之
            padding = 1;
            while (padding <= 2)
            {
                if (pos < 8)
                {
                    plain[pos++] = (byte)(t1 & 0xFF);
                    padding++;
                }
                if (pos == 8)
                    Encrypt8Bytes();
            }

            // 头部填充完了，这里开始填真正的明文了，也是满了8字节就加密，一直到明文读完
            int i2 = offset;
            while (len > 0)
            {
                if (pos < 8)
                {
                    plain[pos++] = input[i2++];
                    len--;
                }
                if (pos == 8)
                    Encrypt8Bytes();
            }

            // 最后填上0，以保证是8字节的倍数
            padding = 1;
            while (padding <= 7)
            {
                if (pos < 8)
                {
                    plain[pos++] = (byte)(0x0);
                    padding++;
                }
                if (pos == 8)
                    Encrypt8Bytes();
            }

            return output;
        }

        /// <param name="input">
        /// 需要加密的明文
        /// </param>
        /// <param name="key">
        /// 密钥
        /// </param>
        /// <returns> Message 密文
        /// </returns>
        public byte[] Encrypt0(byte[] input, byte[] key)
        {
            return Encrypt(input, 0, input.Length, key);
        }

        /// <summary>
        /// 加密一个8字节块
        /// </summary>
        /// <param name="input">
        /// 明文字节数组
        /// </param>
        /// <returns>
        /// 密文字节数组
        /// </returns>
        private byte[] Encipher(byte[] input)
        {
            if (key == null)
            {
                //throwException(@"key is null.");
                return null;
            }
            // 迭代次数，16次
            int loop = 0x10;
            // 得到明文和密钥的各个部分，注意c#有无符号类型，所以为了表示一个无符号的整数
            // 我们用了uint，这个uint的前32位是全0的，我们通过这种方式模拟无符号整数，后面用到的uint也都是一样的
            // 而且为了保证前32位为0，需要和0xFFFFFFFF做一下位与            
            uint y = GetUInt(input, 0, 4);
            uint z = GetUInt(input, 4, 4);
            uint a = GetUInt(key, 0, 4);
            uint b = GetUInt(key, 4, 4);
            uint c = GetUInt(key, 8, 4);
            uint d = GetUInt(key, 12, 4);
            // 这是算法的一些控制变量，为什么delta是0x9E3779B9呢？
            // 这个数是TEA算法的delta，实际是就是sqr(5)-1 * 2^31
            uint sum = 0;
            uint delta = 0x9E3779B9;
            //delta &= unchecked((int) 0xFFFFFFFFL);

            // 开始迭代了，乱七八糟的，我也看不懂，反正和DES之类的差不多，都是这样倒来倒去
            while (loop-- > 0)
            {
                sum += delta;
                //sum &= unchecked((int) 0xFFFFFFFFL);
                y += ((z << 4) + a) ^ (z + sum) ^ (z >> 5) + b;
                //y &= unchecked((int) 0xFFFFFFFFL);
                z += ((y << 4) + c) ^ (y + sum) ^ (y >> 5) + d;
                //z &= unchecked((int) 0xFFFFFFFFL);
            }

            // 最后，我们输出密文，因为我用的uint，所以需要强制转换一下变成int

            return ToBytes(y, z);
        }

        /// <summary>
        /// 解密从offset开始的8字节密文
        /// </summary>
        /// <param name="input">
        /// 密文字节数组
        /// </param>
        /// <param name="offset">
        /// 密文开始位置
        /// </param>
        /// <returns>
        /// 明文
        /// </returns>
        private byte[] Decipher(byte[] input, int offset)
        {
            if (key == null)
            {
                //throwException(@"key is null.");
                return null;
            }
            // 迭代次数，16次
            int loop = 0x10;
            // 得到密文和密钥的各个部分，注意java没有无符号类型，所以为了表示一个无符号的整数
            // 我们用了uint，这个uint的前32位是全0的，我们通过这种方式模拟无符号整数，后面用到的uint也都是一样的
            // 而且为了保证前32位为0，需要和0xFFFFFFFF做一下位与
            uint y = GetUInt(input, offset, 4);
            uint z = GetUInt(input, offset + 4, 4);
            uint a = GetUInt(key, 0, 4);
            uint b = GetUInt(key, 4, 4);
            uint c = GetUInt(key, 8, 4);
            uint d = GetUInt(key, 12, 4);
            // 算法的一些控制变量，为什么sum在这里也有数了呢，这个sum嘛就是和迭代次数有关系了
            // 因为delta是这么多，所以sum如果是这么多的话，迭代的时候减减减，减16次，最后
            // 得到什么？ Yeah，得到0。反正这就是为了得到和加密时相反顺序的控制变量，这样
            // 才能解密呀～～
            uint sum = 0xE3779B90;
            //sum &= unchecked((int) 0xFFFFFFFFL);
            uint delta = 0x9E3779B9;
            //delta &= unchecked((int) 0xFFFFFFFFL);

            // 迭代开始了， #_#
            while (loop-- > 0)
            {
                z -= ((y << 4) + c) ^ (y + sum) ^ ((y >> 5) + d);
                //z &= unchecked((int) 0xFFFFFFFFL);
                y -= ((z << 4) + a) ^ (z + sum) ^ ((z >> 5) + b);
                //y &= unchecked((int) 0xFFFFFFFFL);
                sum -= delta;
                //sum &= unchecked((int) 0xFFFFFFFFL);
            }

            // 输出明文，注意要转成int

            return ToBytes(y, z);
        }

        /// <summary>
        /// 解密
        /// </summary>
        /// <param name="input">
        /// 密文
        /// </param>
        /// <returns>
        /// 明文
        /// </returns>
        private byte[] Decipher(byte[] input)
        {
            return Decipher(input, 0);
        }

        /// <summary>
        /// 加密8字节
        /// </summary>
        private void Encrypt8Bytes()
        {
            // 这部分完成我上面所说的 plain ^ preCrypt，注意这里判断了是不是第一个8字节块，如果是的话，那个prePlain就当作preCrypt用
            for (pos = 0; pos < 8; pos++)
            {
                if (header)
                    plain[pos] ^= prePlain[pos];
                else
                    plain[pos] ^= output[preCrypt + pos];
            }
            // 这个完成到了我上面说的 f(plain ^ preCrypt)
            byte[] crypted = Encipher(plain);
            // 这个没什么，就是拷贝一下，java不像c，所以我只好这么干，c就不用这一步了
            Array.Copy(crypted, 0, output, crypt, 8);

            // 这个就是完成到了 f(plain ^ preCrypt) ^ prePlain，ok，完成了，下面拷贝一下就行了
            for (pos = 0; pos < 8; pos++)
                output[crypt + pos] ^= prePlain[pos];
            Array.Copy(plain, 0, prePlain, 0, 8);

            // 完成了加密，现在是调整crypt，preCrypt等等东西的时候了
            preCrypt = crypt;
            crypt += 8;
            pos = 0;
            header = false;
        }

        /// <summary>
        /// 解密8个字节
        /// </summary>
        /// <param name="input">
        /// 密文字节数组
        /// </param>
        /// <param name="offset">
        /// 从何处开始解密
        /// </param>
        /// <param name="len">
        /// 密文的长度
        /// </param>
        /// <returns>
        /// true表示解密成功
        /// </returns>
        private bool Decrypt8Bytes(byte[] input, int offset, int len)
        {
            // 这里第一步就是判断后面还有没有数据，没有就返回，如果有，就执行 crypt ^ prePlain
            for (pos = 0; pos < 8; pos++)
            {
                if (contextStart + pos >= len)
                    return true;
                prePlain[pos] ^= input[offset + crypt + pos];
            }

            // 好，这里执行到了 d(crypt ^ prePlain)
            prePlain = Decipher(prePlain);
            if (prePlain == null)
                return false;

            // 解密完成，wait，没完成哦，最后一步没做哦？ 
            // 这里最后一步放到Decrypt里面去做了，因为解密的步骤毕竟还是不太一样嘛
            // 调整这些变量的值先
            contextStart += 8;
            crypt += 8;
            pos = 0;
            return true;
        }

        /// <summary> 
        /// 这是个随机因子产生器，用来填充头部的，如果为了调试，可以用一个固定值。
        /// 随机因子可以使相同的明文每次加密出来的密文都不一样。
        /// </summary>
        /// <returns>
        /// 随机因子
        /// </returns>
        private int Rand()
        {
            return xRandom.Next();
        }
        static Tea()
        {
            random = xRandom;
        }
    }

    /// <summary>
    /// 加密/解密出错异常。
    /// </summary>
    public class CrypterException : Exception
    {
        public CrypterException(string message) : base(message)
        {
        }
    }
}