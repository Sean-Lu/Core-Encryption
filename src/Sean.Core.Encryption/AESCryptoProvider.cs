using System;
using System.Security.Cryptography;
using System.Text;
using Sean.Core.Encryption.Enums;
using Sean.Core.Encryption.Extensions;

namespace Sean.Core.Encryption
{
    /// <summary>
    /// AES加密、解密
    /// </summary>
    public class AESCryptoProvider : CryptoBase
    {
        /// <summary>
        /// AES加密
        /// </summary>
        /// <param name="content">待加密字符串</param>
        /// <param name="key">密钥。长度要求小于等于keySize/8</param>
        /// <param name="iv">向量。长度要求小于等于16(大于16自动截断，小于16自动以空格补齐)</param>
        /// <param name="keySize">密匙长度：128位(16个字节)、192位(24个字节)、256位(32个字节)</param>
        /// <param name="encryptMode">加密模式：CBC(推荐)、ECB、OFB、CFB、CTS。ECB模式不使用IV(初始化向量)</param>
        /// <param name="paddingMode">填充模式：None、PKCS7(推荐)、Zeros、ANSIX923、ISO10126</param>
        /// <param name="encodeMode">加密模式</param>
        /// <param name="encoding">编码格式</param>
        /// <returns>密文</returns>
        public static string Encrypt(string content, string key, string iv, int keySize, CipherMode encryptMode, PaddingMode paddingMode, EncodeMode encodeMode = EncodeMode.Base64, Encoding encoding = null)
        {
            encoding = encoding ?? DefaultEncoding;
            int nKeySize = keySize;
            RijndaelManaged rijndaelCipher = new RijndaelManaged
            {
                Mode = encryptMode,
                Padding = paddingMode,
                KeySize = nKeySize,
                BlockSize = 128
            };
            byte[] pwdBytes = encoding.GetBytes(key);
            byte[] ivBytes = { };
            if (encryptMode != CipherMode.ECB)//ECB模式不使用IV(初始化向量)
                ivBytes = encoding.GetBytes(iv.Length > 16 ? iv.Substring(0, 16) : iv.PadRight(16));
            byte[] keyBytes = new byte[nKeySize / 8];
            int len = pwdBytes.Length;
            if (len > keyBytes.Length) len = keyBytes.Length;
            Array.Copy(pwdBytes, keyBytes, len);
            rijndaelCipher.Key = keyBytes;
            if (encryptMode != CipherMode.ECB)//ECB模式不使用IV(初始化向量)
                rijndaelCipher.IV = ivBytes;
            ICryptoTransform transform = rijndaelCipher.CreateEncryptor();
            byte[] plainText = encoding.GetBytes(content);
            byte[] cipherBytes = transform.TransformFinalBlock(plainText, 0, plainText.Length);
            return encodeMode.EncodeToString(cipherBytes, encoding);
        }
        /// <summary>
        /// AES解密
        /// </summary>
        /// <param name="content">待解密字符串</param>
        /// <param name="key">密钥。长度要求小于等于keySize/8</param>
        /// <param name="iv">向量。长度要求小于等于16(大于16自动截断，小于16自动以空格补齐)</param>
        /// <param name="keySize">密匙长度：128位(16个字节)、192位(24个字节)、256位(32个字节)</param>
        /// <param name="encryptMode">加密模式：CBC(推荐)、ECB、OFB、CFB、CTS。ECB模式不使用IV(初始化向量)</param>
        /// <param name="paddingMode">填充模式：None、PKCS7(推荐)、Zeros、ANSIX923、ISO10126</param>
        /// <param name="encodeMode">加密模式</param>
        /// <param name="encoding">编码格式</param>
        /// <returns>明文</returns>
        public static string Decrypt(string content, string key, string iv, int keySize, CipherMode encryptMode, PaddingMode paddingMode, EncodeMode encodeMode = EncodeMode.Base64, Encoding encoding = null)
        {
            encoding = encoding ?? DefaultEncoding;
            int nKeySize = keySize;
            RijndaelManaged rijndaelCipher = new RijndaelManaged
            {
                Mode = encryptMode,
                Padding = paddingMode,
                KeySize = nKeySize,
                BlockSize = 128
            };
            byte[] encryptedData = encodeMode.DecodeToBytes(content, encoding);
            byte[] pwdBytes = encoding.GetBytes(key);
            byte[] ivBytes = { };
            if (encryptMode != CipherMode.ECB)//ECB模式不使用IV(初始化向量)
                ivBytes = encoding.GetBytes(iv.Length > 16 ? iv.Substring(0, 16) : iv.PadRight(16));
            byte[] keyBytes = new byte[nKeySize / 8];
            int len = pwdBytes.Length;
            if (len > keyBytes.Length) len = keyBytes.Length;
            Array.Copy(pwdBytes, keyBytes, len);
            rijndaelCipher.Key = keyBytes;
            if (encryptMode != CipherMode.ECB)//ECB模式不使用IV(初始化向量)
                rijndaelCipher.IV = ivBytes;
            ICryptoTransform transform = rijndaelCipher.CreateDecryptor();
            byte[] plainText = transform.TransformFinalBlock(encryptedData, 0, encryptedData.Length);
            return encoding.GetString(plainText);
        }
    }
}
