
using Sean.Core.Encryption.Enums;
#if !NET40
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Sean.Core.Encryption.Extensions;
using Sean.Utility.Format;

namespace Sean.Core.Encryption
{
    /// <summary>
    /// <para>RSA加密、解密、签名、验签</para>
    /// <para>使用OpenSSL的公钥加密/私钥解密</para>
    /// <para>注：支持跨平台（Windows\Linux\Mac\...）</para>
    /// </summary>
    public class RSACryptoByOpenSslProvider : CryptoBase, IDisposable
    {
        /// <summary>
        /// 数据编码模式
        /// </summary>
        public EncodeMode DefaultDataEncodeMode => _defaultDataEncodeMode;
        /// <summary>
        /// 密匙编码模式
        /// </summary>
        public EncodeMode DefaultKeyEncodeMode => _defaultKeyEncodeMode;
        /// <summary>
        /// 编码格式
        /// </summary>
        public Encoding Encode => _encoding;

        private RSA _rsaProviderFromPublicKey;
        private RSA _rsaProviderFromPrivateKey;
        private readonly HashAlgorithmName _hashAlgorithmName;
        private readonly RSAEncryptionPadding _rsaEncryptionPadding = RSAEncryptionPadding.Pkcs1;
        private readonly RSASignaturePadding _rsaSignaturePadding = RSASignaturePadding.Pkcs1;
        private readonly string _publicKey;
        private readonly string _privateKey;
        private readonly EncodeMode _defaultDataEncodeMode;
        private readonly EncodeMode _defaultKeyEncodeMode;
        private readonly Encoding _encoding;
        private readonly bool _isKeyFromXmlString;

        /// <summary>
        /// 创建RSA实例
        /// </summary>
        /// <param name="rsaType">加密算法类型</param>
        /// <param name="privateKey">私钥</param>
        /// <param name="publicKey">公钥</param>
        /// <param name="defaultDataEncodeMode">数据加密模式</param>
        /// <param name="defaultKeyEncodeMode">密匙加密格式</param>
        /// <param name="encoding">编码格式，默认值：<see cref="CryptoBase.DefaultEncoding"/></param>
        /// <param name="isKeyFromXmlString">密匙是否来自xml【为了兼容由 <see cref="RSA"/>.ToXmlString() 生成的密匙】</param>
        public RSACryptoByOpenSslProvider(RSAType rsaType, string publicKey = null, string privateKey = null, EncodeMode defaultDataEncodeMode = EncodeMode.Base64, EncodeMode defaultKeyEncodeMode = EncodeMode.Base64, Encoding encoding = null, bool isKeyFromXmlString = false)
        {
            //if (string.IsNullOrWhiteSpace(publicKey) && string.IsNullOrWhiteSpace(privateKey))
            //{
            //    throw new Exception("Public key and private key cannot be empty at the same time.");
            //}

            _publicKey = publicKey;
            _privateKey = privateKey;
            _defaultDataEncodeMode = defaultDataEncodeMode;
            _defaultKeyEncodeMode = defaultKeyEncodeMode;
            _encoding = encoding ?? DefaultEncoding;
            _isKeyFromXmlString = isKeyFromXmlString;

            switch (rsaType)
            {
                case RSAType.RSA:
                    _hashAlgorithmName = HashAlgorithmName.SHA1;
                    break;
                case RSAType.RSA2:
                    _hashAlgorithmName = HashAlgorithmName.SHA256;
                    break;
                default:
                    throw new NotSupportedException("Unsupported RSA Type.");
            }
        }

        /// <summary>
        /// 公钥加密
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public string Encrypt(string data)
        {
            return Encrypt(data, _defaultDataEncodeMode);
        }
        /// <summary>
        /// 公钥加密
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public byte[] Encrypt(byte[] data)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));

            InitRsaProviderFromPublicKey();

            //return _rsaProviderFromPublicKey.Encrypt(data, _rsaEncryptionPadding);

            int bufferSize = _rsaProviderFromPublicKey.KeySize / 8 - 11;
            var buffer = new byte[bufferSize];
            using (MemoryStream inputStream = new MemoryStream(data), outputStream = new MemoryStream())
            {
                while (true)
                {
                    // 分段加密
                    int readSize = inputStream.Read(buffer, 0, bufferSize);
                    if (readSize <= 0)
                    {
                        break;
                    }

                    var temp = new byte[readSize];
                    Array.Copy(buffer, 0, temp, 0, readSize);
                    var encryptedBytes = _rsaProviderFromPublicKey.Encrypt(temp, _rsaEncryptionPadding);
                    outputStream.Write(encryptedBytes, 0, encryptedBytes.Length);
                }
                return outputStream.ToArray();
            }
        }
        /// <summary>
        /// 公钥加密
        /// </summary>
        /// <param name="data"></param>
        /// <param name="encodeMode"></param>
        /// <returns></returns>
        public string Encrypt(string data, EncodeMode encodeMode)
        {
            if (string.IsNullOrWhiteSpace(data))
                throw new ArgumentException("Value cannot be null or whitespace.", nameof(data));

            return EncodeEncryptData(Encrypt(_encoding.GetBytes(data)), encodeMode);
        }
        /// <summary>
        /// 公钥加密
        /// </summary>
        /// <param name="data"></param>
        /// <param name="encodeMode"></param>
        /// <returns></returns>
        public string Encrypt<T>(T data, EncodeMode encodeMode)
        {
            return Encrypt(JsonHelper.Serialize(data), encodeMode);
        }

        /// <summary>
        /// 私钥解密
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public string Decrypt(string data)
        {
            return Decrypt(data, _defaultDataEncodeMode);
        }
        /// <summary>
        /// 私钥解密
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public byte[] Decrypt(byte[] data)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));

            InitRsaProviderFromPrivateKey();

            //return _rsaProviderFromPrivateKey.Decrypt(data, _rsaEncryptionPadding);

            int bufferSize = _rsaProviderFromPrivateKey.KeySize / 8;
            var buffer = new byte[bufferSize];
            using (MemoryStream inputStream = new MemoryStream(data), outputStream = new MemoryStream())
            {
                while (true)
                {
                    // 分段解密
                    int readSize = inputStream.Read(buffer, 0, bufferSize);
                    if (readSize <= 0)
                    {
                        break;
                    }

                    var temp = new byte[readSize];
                    Array.Copy(buffer, 0, temp, 0, readSize);
                    var rawBytes = _rsaProviderFromPrivateKey.Decrypt(temp, _rsaEncryptionPadding);
                    outputStream.Write(rawBytes, 0, rawBytes.Length);
                }
                return outputStream.ToArray();
            }
        }
        /// <summary>
        /// 私钥解密
        /// </summary>
        /// <param name="data"></param>
        /// <param name="encodeMode"></param>
        /// <returns></returns>
        public string Decrypt(string data, EncodeMode encodeMode)
        {
            if (string.IsNullOrWhiteSpace(data))
                throw new ArgumentException("Value cannot be null or whitespace.", nameof(data));

            return _encoding.GetString(Decrypt(DecodeEncryptData(data, encodeMode)));
        }
        /// <summary>
        /// 私钥解密
        /// </summary>
        /// <param name="data"></param>
        /// <param name="encodeMode"></param>
        /// <returns></returns>
        public T Decrypt<T>(string data, EncodeMode encodeMode)
        {
            return JsonHelper.Deserialize<T>(Decrypt(data, encodeMode));
        }

        /// <summary>
        /// 私钥签名
        /// </summary>
        /// <param name="data">原始数据</param>
        /// <returns></returns>
        public string Sign(string data)
        {
            return Sign(data, _defaultDataEncodeMode);
        }
        /// <summary>
        /// 私钥签名
        /// </summary>
        /// <param name="data">原始数据</param>
        /// <returns></returns>
        public byte[] Sign(byte[] data)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));

            InitRsaProviderFromPrivateKey();

            return _rsaProviderFromPrivateKey.SignData(data, _hashAlgorithmName, _rsaSignaturePadding);
        }
        /// <summary>
        /// 私钥签名
        /// </summary>
        /// <param name="data">原始数据</param>
        /// <param name="encodeMode"></param>
        /// <returns></returns>
        public string Sign(string data, EncodeMode encodeMode)
        {
            if (string.IsNullOrWhiteSpace(data))
                throw new ArgumentException("Value cannot be null or whitespace.", nameof(data));

            return EncodeEncryptData(Sign(_encoding.GetBytes(data)), encodeMode);
        }

        /// <summary>
        /// 公钥验签
        /// </summary>
        /// <param name="data">原始数据</param>
        /// <param name="sign">签名</param>
        /// <returns></returns>
        public bool Verify(string data, string sign)
        {
            return Verify(data, sign, _defaultDataEncodeMode);
        }
        /// <summary>
        /// 公钥验签
        /// </summary>
        /// <param name="data">原始数据</param>
        /// <param name="sign">签名</param>
        /// <returns></returns>
        public bool Verify(byte[] data, byte[] sign)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            if (sign == null) throw new ArgumentNullException(nameof(sign));

            InitRsaProviderFromPublicKey();

            return _rsaProviderFromPublicKey.VerifyData(data, sign, _hashAlgorithmName, _rsaSignaturePadding);
        }
        /// <summary>
        /// 公钥验签
        /// </summary>
        /// <param name="data">原始数据</param>
        /// <param name="sign">签名</param>
        /// <param name="encodeMode"></param>
        /// <returns></returns>
        public bool Verify(string data, string sign, EncodeMode encodeMode)
        {
            if (string.IsNullOrWhiteSpace(data))
                throw new ArgumentException("Value cannot be null or whitespace.", nameof(data));
            if (string.IsNullOrWhiteSpace(sign))
                throw new ArgumentException("Value cannot be null or whitespace.", nameof(sign));

            return Verify(_encoding.GetBytes(data), DecodeEncryptData(sign, encodeMode));
        }

        /// <summary>
        /// 使用私钥创建RSA实例
        /// </summary>
        /// <param name="privateKey">私钥</param>
        /// <param name="keyEncodeMode">密匙编码模式</param>
        /// <param name="encoding">编码格式</param>
        /// <param name="isKeyFromXmlString">密匙是否来自xml【为了兼容由 <see cref="RSA"/>.ToXmlString() 生成的密匙】</param>
        /// <returns></returns>
        public static RSA CreateRsaProviderFromPrivateKey(string privateKey, EncodeMode keyEncodeMode = EncodeMode.Base64, Encoding encoding = null, bool isKeyFromXmlString = false)
        {
            if (string.IsNullOrWhiteSpace(privateKey))
                throw new ArgumentException("Value cannot be null or whitespace.", nameof(privateKey));

            encoding = encoding ?? DefaultEncoding;

            var rsa = RSA.Create();
            if (isKeyFromXmlString)
            {
                rsa.FromXmlString(GetKeyFromXml(privateKey, keyEncodeMode, encoding));
                return rsa;
            }
            var rsaParameters = new RSAParameters();

            var privateKeyBits = GetKey(privateKey, keyEncodeMode, encoding);
            using (var mem = new MemoryStream(privateKeyBits))
            {
                using (var binaryReader = new BinaryReader(mem))
                {
                    byte bt = 0;
                    ushort twobytes = 0;
                    twobytes = binaryReader.ReadUInt16();
                    if (twobytes == 0x8130)
                        binaryReader.ReadByte();
                    else if (twobytes == 0x8230)
                        binaryReader.ReadInt16();
                    else
                        throw new Exception("Unexpected value read binr.ReadUInt16()");

                    twobytes = binaryReader.ReadUInt16();
                    if (twobytes != 0x0102)
                        throw new Exception("Unexpected version");

                    bt = binaryReader.ReadByte();
                    if (bt != 0x00)
                        throw new Exception("Unexpected value read binr.ReadByte()");

                    rsaParameters.Modulus = binaryReader.ReadBytes(GetIntegerSize(binaryReader));
                    rsaParameters.Exponent = binaryReader.ReadBytes(GetIntegerSize(binaryReader));
                    rsaParameters.D = binaryReader.ReadBytes(GetIntegerSize(binaryReader));
                    rsaParameters.P = binaryReader.ReadBytes(GetIntegerSize(binaryReader));
                    rsaParameters.Q = binaryReader.ReadBytes(GetIntegerSize(binaryReader));
                    rsaParameters.DP = binaryReader.ReadBytes(GetIntegerSize(binaryReader));
                    rsaParameters.DQ = binaryReader.ReadBytes(GetIntegerSize(binaryReader));
                    rsaParameters.InverseQ = binaryReader.ReadBytes(GetIntegerSize(binaryReader));
                }
            }

            rsa.ImportParameters(rsaParameters);
            return rsa;
        }

        /// <summary>
        /// 使用公钥创建RSA实例
        /// </summary>
        /// <param name="publicKey">私钥</param>
        /// <param name="keyEncodeMode">密匙编码模式</param>
        /// <param name="encoding">编码格式</param>
        /// <param name="isKeyFromXmlString">密匙是否来自xml【为了兼容由 <see cref="RSA"/>.ToXmlString() 生成的密匙】</param>
        /// <returns></returns>
        public static RSA CreateRsaProviderFromPublicKey(string publicKey, EncodeMode keyEncodeMode = EncodeMode.Base64, Encoding encoding = null, bool isKeyFromXmlString = false)
        {
            if (string.IsNullOrWhiteSpace(publicKey))
                throw new ArgumentException("Value cannot be null or whitespace.", nameof(publicKey));

            encoding = encoding ?? DefaultEncoding;

            // ------- create RSACryptoServiceProvider instance and initialize with public key -----
            // System.Security.Cryptography.RSA.Create() 工厂方法，使用它之后，在 Windows 上创建的是 System.Security.Cryptography.RSACng 的实例，在 Mac 与 Linux 上创建的是 System.Security.Cryptography.RSAOpenSsl 的实例，它们都继承自 System.Security.Cryptography.RSA 抽象类。
            var rsa = RSA.Create();
            if (isKeyFromXmlString)
            {
                rsa.FromXmlString(GetKeyFromXml(publicKey, keyEncodeMode, encoding));
                return rsa;
            }
            var rsaParameters = new RSAParameters();

            // ---------  Set up stream to read the asn.1 encoded SubjectPublicKeyInfo blob  ------
            var x509Key = GetKey(publicKey, keyEncodeMode, encoding);
            using (var mem = new MemoryStream(x509Key))
            {
                using (var binaryReader = new BinaryReader(mem))  //wrap Memory Stream with BinaryReader for easy reading
                {
                    byte bt = 0;
                    ushort twobytes = 0;

                    twobytes = binaryReader.ReadUInt16();
                    if (twobytes == 0x8130) //data read as little endian order (actual data order for Sequence is 30 81)
                        binaryReader.ReadByte();    //advance 1 byte
                    else if (twobytes == 0x8230)
                        binaryReader.ReadInt16();   //advance 2 bytes
                    else
                        return null;

                    // encoded OID sequence for  PKCS #1 rsaEncryption szOID_RSA_RSA = "1.2.840.113549.1.1.1"
                    byte[] seqOid = { 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00 };
                    byte[] seq = new byte[15];

                    seq = binaryReader.ReadBytes(15);       //read the Sequence OID
                    if (!CompareBytearrays(seq, seqOid))    //make sure Sequence for OID is correct
                        return null;

                    twobytes = binaryReader.ReadUInt16();
                    if (twobytes == 0x8103) //data read as little endian order (actual data order for Bit String is 03 81)
                        binaryReader.ReadByte();    //advance 1 byte
                    else if (twobytes == 0x8203)
                        binaryReader.ReadInt16();   //advance 2 bytes
                    else
                        return null;

                    bt = binaryReader.ReadByte();
                    if (bt != 0x00)     //expect null byte next
                        return null;

                    twobytes = binaryReader.ReadUInt16();
                    if (twobytes == 0x8130) //data read as little endian order (actual data order for Sequence is 30 81)
                        binaryReader.ReadByte();    //advance 1 byte
                    else if (twobytes == 0x8230)
                        binaryReader.ReadInt16();   //advance 2 bytes
                    else
                        return null;

                    twobytes = binaryReader.ReadUInt16();
                    byte lowbyte = 0x00;
                    byte highbyte = 0x00;

                    if (twobytes == 0x8102) //data read as little endian order (actual data order for Integer is 02 81)
                        lowbyte = binaryReader.ReadByte();  // read next bytes which is bytes in modulus
                    else if (twobytes == 0x8202)
                    {
                        highbyte = binaryReader.ReadByte(); //advance 2 bytes
                        lowbyte = binaryReader.ReadByte();
                    }
                    else
                        return null;
                    byte[] modint = { lowbyte, highbyte, 0x00, 0x00 };   //reverse byte order since asn.1 key uses big endian order
                    int modsize = BitConverter.ToInt32(modint, 0);

                    int firstbyte = binaryReader.PeekChar();
                    if (firstbyte == 0x00)
                    {   //if first byte (highest order) of modulus is zero, don't include it
                        binaryReader.ReadByte();    //skip this null byte
                        modsize -= 1;   //reduce modulus buffer size by 1
                    }

                    byte[] modulus = binaryReader.ReadBytes(modsize);   //read the modulus bytes

                    if (binaryReader.ReadByte() != 0x02)            //expect an Integer for the exponent data
                        return null;
                    int expbytes = (int)binaryReader.ReadByte();        // should only need one byte for actual exponent data (for all useful values)
                    byte[] exponent = binaryReader.ReadBytes(expbytes);

                    rsaParameters.Modulus = modulus;
                    rsaParameters.Exponent = exponent;
                }
            }

            rsa.ImportParameters(rsaParameters);
            return rsa;
        }

        /// <summary>
        /// 生成RSA的公钥和私钥
        /// </summary>
        /// <param name="xmlPublicKey">公钥</param>
        /// <param name="xmlPrivateKey">私钥</param>
        /// <param name="encodeMode">编码模式</param>
        /// <param name="encoding">编码格式，默认值：<see cref="CryptoBase.DefaultEncoding"/></param>
        public static void GenerateXmlKey(out string xmlPublicKey, out string xmlPrivateKey, EncodeMode encodeMode = EncodeMode.None, Encoding encoding = null)
        {
            encoding = encoding ?? DefaultEncoding;

            using (var rsa = RSA.Create())
            {
                xmlPublicKey = encodeMode.EncodeToString(rsa.ToXmlString(false), encoding);
                xmlPrivateKey = encodeMode.EncodeToString(rsa.ToXmlString(true), encoding);
            }
        }

        /// <summary>
        /// 资源销毁
        /// </summary>
        public void Dispose()
        {
            _rsaProviderFromPublicKey?.Dispose();
            _rsaProviderFromPrivateKey?.Dispose();
        }

        #region Private Methods
        private static int GetIntegerSize(BinaryReader binr)
        {
            byte bt = 0;
            int count = 0;
            bt = binr.ReadByte();
            if (bt != 0x02)
                return 0;
            bt = binr.ReadByte();

            if (bt == 0x81)
                count = binr.ReadByte();
            else
            if (bt == 0x82)
            {
                var highbyte = binr.ReadByte();
                var lowbyte = binr.ReadByte();
                byte[] modint = { lowbyte, highbyte, 0x00, 0x00 };
                count = BitConverter.ToInt32(modint, 0);
            }
            else
            {
                count = bt;
            }

            while (binr.ReadByte() == 0x00)
            {
                count -= 1;
            }
            binr.BaseStream.Seek(-1, SeekOrigin.Current);
            return count;
        }

        private static bool CompareBytearrays(byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
                return false;
            int i = 0;
            foreach (byte c in a)
            {
                if (c != b[i])
                    return false;
                i++;
            }
            return true;
        }

        private void InitRsaProviderFromPublicKey()
        {
            if (_rsaProviderFromPublicKey != null)
            {
                return;
            }

            _rsaProviderFromPublicKey = CreateRsaProviderFromPublicKey(_publicKey, _defaultKeyEncodeMode, _encoding, _isKeyFromXmlString) ?? throw new Exception("Create RSA provider from public key fail.");
        }

        private void InitRsaProviderFromPrivateKey()
        {
            if (_rsaProviderFromPrivateKey != null)
            {
                return;
            }

            _rsaProviderFromPrivateKey = CreateRsaProviderFromPrivateKey(_privateKey, _defaultKeyEncodeMode, _encoding, _isKeyFromXmlString) ?? throw new Exception("Create RSA provider from private key fail.");
        }

        /// <summary>
        /// 对加密数据进行编码（EncodeMode: <see cref="DefaultDataEncodeMode"/>）
        /// </summary>
        /// <param name="encryptData">加密数据</param>
        /// <returns></returns>
        private string EncodeEncryptData(byte[] encryptData, EncodeMode encodeMode)
        {
            return encodeMode.EncodeToString(encryptData, _encoding);
        }
        /// <summary>
        /// 对加密数据进行解码（EncodeMode: <see cref="DefaultDataEncodeMode"/>）
        /// </summary>
        /// <param name="encryptData">加密数据</param>
        /// <returns></returns>
        private byte[] DecodeEncryptData(string encryptData, EncodeMode encodeMode)
        {
            return encodeMode.DecodeToBytes(encryptData, _encoding);
        }

        private static byte[] GetKey(string key, EncodeMode keyEncodeMode, Encoding encoding)
        {
            return keyEncodeMode.DecodeToBytes(key, encoding);
        }
        private static string GetKeyFromXml(string key, EncodeMode keyEncodeMode, Encoding encoding)
        {
            return keyEncodeMode.DecodeToString(key, encoding);
        }
        #endregion
    }
}
#endif