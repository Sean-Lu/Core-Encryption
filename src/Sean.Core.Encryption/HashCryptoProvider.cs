using System;
using System.Security.Cryptography;
using System.Text;
using Sean.Core.Encryption.Enums;
using Sean.Utility.Format;

namespace Sean.Core.Encryption
{
    /// <summary>
    /// Hash（哈希）加密、解密
    /// </summary>
    public class HashCryptoProvider : CryptoBase
    {
        #region Md5(Message-Digest Algorithm 5)：消息摘要算法第五版
        /// <summary>
        /// Md5加密(4位)
        /// </summary>
        /// <param name="content">待加密字符串</param>
        /// <returns>密文</returns>
        public static string Md5Encrypt4(string content)
        {
            return Md5Encrypt32(content)?.Substring(8, 4);
        }
        /// <summary>
        /// Md5加密(8位)
        /// </summary>
        /// <param name="content">待加密字符串</param>
        /// <returns>密文</returns>
        public static string Md5Encrypt8(string content)
        {
            return Md5Encrypt32(content)?.Substring(8, 8);
        }
        /// <summary>
        /// Md5加密(16位)。取32位的中间部分,即9~24位。
        /// </summary>
        /// <param name="content">待加密字符串</param>
        /// <returns>密文</returns>
        public static string Md5Encrypt16(string content)
        {
            return Md5Encrypt32(content)?.Substring(8, 16);
        }
        /// <summary>
        /// Md5加密(32位)
        /// </summary>
        /// <param name="content">待加密字符串</param>
        /// <returns>密文</returns>
        public static string Md5Encrypt32(string content)
        {
            return Hash(content, new MD5CryptoServiceProvider(), EncodeMode.Hex);
        }
        #endregion

        #region SHA(Secure Hash Algorithm)：安全哈希算法
        /// <summary>
        /// SHA1加密
        /// </summary>
        /// <param name="content">待加密字符串</param>
        /// <param name="encodeMode">加密模式</param>
        /// <returns>密文</returns>
        public static string Sha1Encrypt(string content, EncodeMode encodeMode = EncodeMode.Hex)
        {
            return Hash(content, new SHA1CryptoServiceProvider(), encodeMode);
        }
        /// <summary>
        /// SHA256加密
        /// </summary>
        /// <param name="content">待加密字符串</param>
        /// <param name="encodeMode">加密模式</param>
        /// <returns>密文</returns>
        public static string Sha256Encrypt(string content, EncodeMode encodeMode = EncodeMode.Hex)
        {
            return Hash(content, new SHA256Managed(), encodeMode);
        }
        /// <summary>
        /// SHA384加密
        /// </summary>
        /// <param name="content">待加密字符串</param>
        /// <param name="encodeMode">加密模式</param>
        /// <returns>密文</returns>
        public static string Sha384Encrypt(string content, EncodeMode encodeMode = EncodeMode.Hex)
        {
            return Hash(content, new SHA384Managed(), encodeMode);
        }
        /// <summary>
        /// SHA512加密
        /// </summary>
        /// <param name="content">待加密字符串</param>
        /// <param name="encodeMode">加密模式</param>
        /// <returns>密文</returns>
        public static string Sha512Encrypt(string content, EncodeMode encodeMode = EncodeMode.Hex)
        {
            return Hash(content, new SHA512Managed(), encodeMode);
        }
        #endregion

        /// <summary>
        /// Hash加密
        /// </summary>
        /// <param name="content">待加密字符串</param>
        /// <param name="hashAlgorithm">hash算法</param>
        /// <param name="encodeMode">加密模式</param>
        /// <param name="encoding">编码格式</param>
        /// <returns></returns>
        public static string Hash(string content, HashAlgorithm hashAlgorithm, EncodeMode encodeMode = EncodeMode.Hex, Encoding encoding = null)
        {
            if (hashAlgorithm == null) throw new ArgumentNullException(nameof(hashAlgorithm));
            if (string.IsNullOrWhiteSpace(content)) throw new Exception("内容不能为空");

            encoding = encoding ?? DefaultEncoding;
            var hash = hashAlgorithm.ComputeHash(encoding.GetBytes(content));
            hashAlgorithm.Clear();

            string result;
            switch (encodeMode)
            {
                case EncodeMode.Hex:
                    result = ConvertHelper.ToHexString(hash, string.Empty);
                    break;
                case EncodeMode.Base64:
                    result = Convert.ToBase64String(hash);
                    break;
                default:
                    result = string.Empty;
                    break;
            }
            return result;
        }

        /// <summary>
        /// 加密密码（MD5）
        /// </summary>
        /// <param name="password">密码</param>
        /// <returns>密文</returns>
        public static string HashPasswordByMd5(string password)
        {
            return Md5Encrypt32(password);
        }
        /// <summary>
        /// 加密密码（SHA1）
        /// </summary>
        /// <param name="password">密码</param>
        /// <returns>密文</returns>
        public static string HashPasswordBySha1(string password)
        {
            return Sha1Encrypt(password);
        }
    }
}
