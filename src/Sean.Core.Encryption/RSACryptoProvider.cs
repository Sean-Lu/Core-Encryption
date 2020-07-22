using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Sean.Core.Encryption.Enums;
using Sean.Core.Encryption.Extensions;
using Sean.Utility.Format;

namespace Sean.Core.Encryption
{
    /// <summary>
    /// <para>RSA加密、解密、签名、验签</para>
    /// <para>如需在非windows平台下使用，请使用<see cref="RSACryptoByOpenSslProvider"/></para>
    /// <para>注：基于<see cref="RSACryptoServiceProvider"/>这个类，这个类并不支持跨平台，所以如果你是用这个类来进行加/解密，在windows上运行是完全没有错误的，但是只要你一放到Linux下就会出现异常。</para>
    /// </summary>
    public class RSACryptoProvider : CryptoBase
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

        private readonly EncodeMode _defaultDataEncodeMode;
        private readonly EncodeMode _defaultKeyEncodeMode;
        private readonly Encoding _encoding;

        /// <summary>
        /// 创建RSA实例
        /// </summary>
        /// <param name="defaultDataEncodeMode">数据加密模式</param>
        /// <param name="defaultKeyEncodeMode">密匙加密格式</param>
        /// <param name="encoding">编码格式，默认值：<see cref="CryptoBase.DefaultEncoding"/></param>
        public RSACryptoProvider(EncodeMode defaultDataEncodeMode = EncodeMode.Base64, EncodeMode defaultKeyEncodeMode = EncodeMode.Base64, Encoding encoding = null)
        {
            _defaultDataEncodeMode = defaultDataEncodeMode;
            _defaultKeyEncodeMode = defaultKeyEncodeMode;
            _encoding = encoding ?? DefaultEncoding;
        }

        /// <summary>
        /// 公钥加密
        /// </summary>
        /// <param name="data">待加密的字符串</param>
        /// <param name="publicKey">公钥</param>
        /// <returns>密文字符串</returns>
        public string Encrypt(string data, string publicKey)
        {
            return Encrypt(data, publicKey, _defaultDataEncodeMode);
        }
        /// <summary>
        /// 公钥加密
        /// </summary>
        /// <param name="data">待加密的字符串</param>
        /// <param name="publicKey">公钥</param>
        /// <param name="encodeMode"></param>
        /// <returns>密文字符串</returns>
        public string Encrypt(string data, string publicKey, EncodeMode encodeMode)
        {
            if (string.IsNullOrWhiteSpace(data))
                throw new ArgumentException("Value cannot be null or whitespace.", nameof(data));
            if (string.IsNullOrWhiteSpace(publicKey))
                throw new ArgumentException("Value cannot be null or whitespace.", nameof(publicKey));

            return encodeMode.EncodeToString(Encrypt(_encoding.GetBytes(data), publicKey), _encoding);
        }
        /// <summary>
        /// 公钥加密
        /// </summary>
        /// <param name="data">待加密的字节数组</param>
        /// <param name="publicKey">公钥</param>
        /// <returns>密文字符串</returns>
        public byte[] Encrypt(byte[] data, string publicKey)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            if (string.IsNullOrWhiteSpace(publicKey))
                throw new ArgumentException("Value cannot be null or whitespace.", nameof(publicKey));

            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString(GetKeyFromXml(publicKey));
                //return rsa.Encrypt(data, false);

                // 使用非对称密钥加密数据时，一次加密的数据长度是：密钥长度/8-11，超过这个大小会报错：The message exceeds the maximum allowable length for the chosen options (117).
                // 如果key的长度为1024位，1024/8 - 11 = 117，一次加密内容不能超过117bytes。
                // 如果key的长度为2048位，2048/8 - 11 = 245，一次加密内容不能超过245bytes。
                int bufferSize = rsa.KeySize / 8 - 11;//单块最大长度
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
                        var encryptedBytes = rsa.Encrypt(temp, false);
                        outputStream.Write(encryptedBytes, 0, encryptedBytes.Length);
                    }
                    return outputStream.ToArray();
                }
            }
        }
        /// <summary>
        /// 公钥加密
        /// </summary>
        /// <param name="data">待加密的字符串</param>
        /// <param name="publicKey">公钥</param>
        /// <param name="encodeMode"></param>
        /// <returns>密文字符串</returns>
        public string Encrypt<T>(T data, string publicKey, EncodeMode encodeMode)
        {
            return Encrypt(JsonHelper.Serialize(data), publicKey, encodeMode);
        }

        /// <summary>
        /// 私钥解密
        /// </summary>
        /// <param name="data">待解密的字符串</param>
        /// <param name="privateKey">私钥</param>
        /// <returns>明文字符串</returns>
        public string Decrypt(string data, string privateKey)
        {
            return Decrypt(data, privateKey, _defaultDataEncodeMode);
        }
        /// <summary>
        /// 私钥解密
        /// </summary>
        /// <param name="data">待解密的字符串</param>
        /// <param name="privateKey">私钥</param>
        /// <param name="encodeMode"></param>
        /// <returns>明文字符串</returns>
        public string Decrypt(string data, string privateKey, EncodeMode encodeMode)
        {
            if (string.IsNullOrWhiteSpace(data))
                throw new ArgumentException("Value cannot be null or whitespace.", nameof(data));
            if (string.IsNullOrWhiteSpace(privateKey))
                throw new ArgumentException("Value cannot be null or whitespace.", nameof(privateKey));

            return _encoding.GetString(Decrypt(encodeMode.DecodeToBytes(data, _encoding), privateKey));
        }
        /// <summary>
        /// 私钥解密
        /// </summary>
        /// <param name="data">待解密的字节数组</param>
        /// <param name="privateKey">私钥</param>
        /// <returns>明文字符串</returns>
        public byte[] Decrypt(byte[] data, string privateKey)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            if (string.IsNullOrWhiteSpace(privateKey))
                throw new ArgumentException("Value cannot be null or whitespace.", nameof(privateKey));

            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString(GetKeyFromXml(privateKey));
                //return rsa.Decrypt(data, false);

                int bufferSize = rsa.KeySize / 8;
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
                        var rawBytes = rsa.Decrypt(temp, false);
                        outputStream.Write(rawBytes, 0, rawBytes.Length);
                    }
                    return outputStream.ToArray();
                }
            }
        }
        /// <summary>
        /// 私钥解密
        /// </summary>
        /// <param name="data">待解密的字符串</param>
        /// <param name="privateKey">私钥</param>
        /// <param name="encodeMode"></param>
        /// <returns>明文字符串</returns>
        public T Decrypt<T>(string data, string privateKey, EncodeMode encodeMode)
        {
            return JsonHelper.Deserialize<T>(Decrypt(data, privateKey, encodeMode));
        }

        /// <summary>  
        /// 私钥签名
        /// </summary>
        /// <param name="data">待签名字符串</param>
        /// <param name="privateKey">私钥</param>
        /// <returns></returns>
        public string Sign(string data, string privateKey)
        {
            return Sign(data, privateKey, _defaultDataEncodeMode);
        }
        /// <summary>  
        /// 私钥签名
        /// </summary>
        /// <param name="data">待签名字符串</param>
        /// <param name="privateKey">私钥</param>
        /// <param name="encodeMode"></param>
        /// <returns></returns>
        public string Sign(string data, string privateKey, EncodeMode encodeMode)
        {
            if (string.IsNullOrWhiteSpace(data))
                throw new ArgumentException("Value cannot be null or whitespace.", nameof(data));
            if (string.IsNullOrWhiteSpace(privateKey))
                throw new ArgumentException("Value cannot be null or whitespace.", nameof(privateKey));

            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString(GetKeyFromXml(privateKey));
                var buffer = _encoding.GetBytes(data);
                var signData = rsa.SignData(buffer, new SHA1CryptoServiceProvider());
                return encodeMode.EncodeToString(signData, _encoding);
            }
        }

        /// <summary>  
        /// 公钥验签
        /// </summary>
        /// <param name="data">待验签字符串</param>
        /// <param name="signature">签名</param>
        /// <param name="publicKey">公钥</param>
        /// <returns></returns>
        public bool Verify(string data, string signature, string publicKey)
        {
            return Verify(data, signature, publicKey, _defaultDataEncodeMode);
        }
        /// <summary>  
        /// 公钥验签
        /// </summary>
        /// <param name="data">待验签字符串</param>
        /// <param name="signature">签名</param>
        /// <param name="publicKey">公钥</param>
        /// <param name="encodeMode"></param>
        /// <returns></returns>
        public bool Verify(string data, string signature, string publicKey, EncodeMode encodeMode)
        {
            if (string.IsNullOrWhiteSpace(data))
                throw new ArgumentException("Value cannot be null or whitespace.", nameof(data));
            if (string.IsNullOrWhiteSpace(signature))
                throw new ArgumentException("Value cannot be null or whitespace.", nameof(signature));
            if (string.IsNullOrWhiteSpace(publicKey))
                throw new ArgumentException("Value cannot be null or whitespace.", nameof(publicKey));

            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString(GetKeyFromXml(publicKey));
                var buffer = _encoding.GetBytes(data);
                var signatureData = encodeMode.DecodeToBytes(signature, _encoding);
                return rsa.VerifyData(buffer, new SHA1CryptoServiceProvider(), signatureData);
            }
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

            using (var rsa = new RSACryptoServiceProvider())
            {
                xmlPublicKey = encodeMode.EncodeToString(rsa.ToXmlString(false), encoding);
                xmlPrivateKey = encodeMode.EncodeToString(rsa.ToXmlString(true), encoding);
            }
        }

        #region Private Methods
        private string GetKeyFromXml(string key)
        {
            return _defaultKeyEncodeMode.DecodeToString(key, _encoding);
        }
        #endregion
    }
}
