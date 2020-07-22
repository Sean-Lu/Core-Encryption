using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Sean.Core.Encryption
{
    /// <summary>
    /// RC2加密、解密
    /// </summary>
    public class RC2CryptoProvider : CryptoBase
    {
        /// <summary>
        /// RC2 加密(用变长密钥对大量数据进行加密)
        /// </summary>
        /// <param name="content">待加密字符串</param>
        /// <param name="encryptKey">密匙，密钥必须为5-16位。</param>
        /// <param name="encoding">编码格式</param>
        /// <returns>密文</returns>
        public static string Encrypt(string content, string encryptKey, Encoding encoding = null)
        {
            if (content == null) throw new ArgumentNullException(nameof(content));
            if (encryptKey == null) throw new ArgumentNullException(nameof(encryptKey));
            if (encryptKey.Length < 5 || encryptKey.Length > 16) throw new Exception("密钥必须为5-16位");

            encoding = encoding ?? DefaultEncoding;
            string strEncrypt = "";
            byte[] btIv = { 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF };
            //RC2CryptoServiceProvider 实现支持的密钥长度为从 40 位到 128 位（即5-16字节），以 8 位递增。
            using (var rc2Provider = new RC2CryptoServiceProvider())
            {
                try
                {
                    byte[] btEncryptString = encoding.GetBytes(content);
                    using (var ms = new MemoryStream())
                    {
                        using (var cs = new CryptoStream(ms, rc2Provider.CreateEncryptor(encoding.GetBytes(encryptKey), btIv), CryptoStreamMode.Write))
                        {
                            cs.Write(btEncryptString, 0, btEncryptString.Length);
                            cs.FlushFinalBlock();
                            strEncrypt = Convert.ToBase64String(ms.ToArray());
                            ms.Close();
                            ms.Dispose();
                            cs.Close();
                            cs.Dispose();
                        }
                    }
                }
                finally { rc2Provider.Clear(); }
            }

            return strEncrypt;
        }
        /// <summary>
        /// RC2 解密(用变长密钥对大量数据进行加密)
        /// </summary>
        /// <param name="content">待解密字符串</param>
        /// <param name="decryptKey">密匙，密钥必须为5-16位。</param>
        /// <param name="encoding">编码格式</param>
        /// <returns>明文</returns>
        public static string Decrypt(string content, string decryptKey, Encoding encoding = null)
        {
            if (content == null) throw new ArgumentNullException(nameof(content));
            if (decryptKey == null) throw new ArgumentNullException(nameof(decryptKey));
            if (decryptKey.Length < 5 || decryptKey.Length > 16) throw new Exception("密钥必须为5-16位");

            encoding = encoding ?? DefaultEncoding;
            byte[] btIv = { 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF };
            string strDecrypt = "";
            //RC2CryptoServiceProvider 实现支持的密钥长度为从 40 位到 128 位（即5-16字节），以 8 位递增。
            using (var rc2Provider = new RC2CryptoServiceProvider())
            {
                try
                {
                    byte[] btDecryptString = Convert.FromBase64String(content);
                    using (var ms = new MemoryStream())
                    {
                        using (var cs = new CryptoStream(ms, rc2Provider.CreateDecryptor(encoding.GetBytes(decryptKey), btIv), CryptoStreamMode.Write))
                        {
                            cs.Write(btDecryptString, 0, btDecryptString.Length);
                            cs.FlushFinalBlock();
                            strDecrypt = encoding.GetString(ms.ToArray());
                            ms.Close();
                            ms.Dispose();
                            cs.Close();
                            cs.Dispose();
                        }
                    }
                }
                finally { rc2Provider.Clear(); }
            }

            return strDecrypt;
        }
    }
}
