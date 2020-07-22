using System;
using System.Text;

namespace Sean.Core.Encryption
{
    /// <summary>
    /// Base64编码、解码
    /// </summary>
    public class Base64CryptoProvider : CryptoBase
    {
        /// <summary>
        /// Base64编码
        /// </summary>
        /// <param name="content">待编码字符串</param>
        /// <param name="encoding">编码格式</param>
        /// <returns>密文</returns>
        public static string Encrypt(string content, Encoding encoding = null)
        {
            encoding = encoding ?? DefaultEncoding;
            return EncryptFromByte(encoding.GetBytes(content));
        }
        /// <summary>
        /// Base64解码
        /// </summary>
        /// <param name="content">待解码字符串</param>
        /// <param name="encoding">编码格式</param>
        /// <returns>明文</returns>
        public static string Decrypt(string content, Encoding encoding = null)
        {
            encoding = encoding ?? DefaultEncoding;
            return encoding.GetString(DecryptToByte(content));
        }

        /// <summary>
        /// Base64编码
        /// </summary>
        /// <param name="data">待编码字节数组</param>
        /// <returns>密文</returns>
        public static string EncryptFromByte(byte[] data)
        {
            return Convert.ToBase64String(data);
        }
        /// <summary>
        /// Base64解码
        /// </summary>
        /// <param name="data">待解码Base64字符串</param>
        /// <returns>明文</returns>
        public static byte[] DecryptToByte(string data)
        {
            return Convert.FromBase64String(data);
        }
    }
}
