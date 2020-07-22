using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Sean.Core.Encryption.Enums;
using Sean.Core.Encryption.Extensions;

namespace Sean.Core.Encryption
{
    /// <summary>
    /// DES加密、解密
    /// </summary>
    public class DESCryptoProvider : CryptoBase
    {
        private const string InvalidDesKey = "非法的DES密钥（最大长度为8位）";

        #region DES
        /// <summary>
        /// DES加密
        /// </summary>
        /// <param name="content">待加密字符串</param>
        /// <param name="encryptKey">密匙(要求为8位，不足8位会自动用空格填充以达到8位的长度要求)</param>
        /// <param name="encodeMode">加密模式</param>
        /// <param name="encoding">编码格式</param>
        /// <returns>Base64或16进制密文</returns>
        public static string Encrypt(string content, string encryptKey, EncodeMode encodeMode = EncodeMode.Base64, Encoding encoding = null)
        {
            if (encryptKey.Length > 8) throw new Exception(InvalidDesKey);

            encoding = encoding ?? DefaultEncoding;
            using (var des = new DESCryptoServiceProvider())
            {
                des.Key = encoding.GetBytes(encryptKey.PadRight(8));
                des.IV = des.Key;
                using (var encryptor = des.CreateEncryptor())
                {
                    var data = encoding.GetBytes(content);
                    var result = encryptor.TransformFinalBlock(data, 0, data.Length);
                    return encodeMode.EncodeToString(result, encoding);
                }
            }
        }
        /// <summary>
        /// DES解密
        /// </summary>
        /// <param name="content">待解密字符串</param>
        /// <param name="decryptKey">密匙(要求为8位，不足8位会自动用空格填充以达到8位的长度要求)</param>
        /// <param name="encodeMode">加密模式</param>
        /// <param name="encoding">编码格式</param>
        /// <returns>明文</returns>
        public static string Decrypt(string content, string decryptKey, EncodeMode encodeMode = EncodeMode.Base64, Encoding encoding = null)
        {
            if (decryptKey.Length > 8) throw new Exception(InvalidDesKey);

            encoding = encoding ?? DefaultEncoding;
            using (var des = new DESCryptoServiceProvider())
            {
                des.Key = encoding.GetBytes(decryptKey.PadRight(8));
                des.IV = des.Key;
                using (var decryptor = des.CreateDecryptor())
                {
                    byte[] data = encodeMode.DecodeToBytes(content, encoding);
                    var result = decryptor.TransformFinalBlock(data, 0, data.Length);
                    return encoding.GetString(result);
                }
            }
        }
        /// <summary>
        /// DES加密文件
        /// </summary>
        /// <param name="sourceFilePath">待加密文件</param>
        /// <param name="destinationFilePath">加密后的文件保存路径</param>
        /// <param name="encryptKey">密钥(要求为8位，不足8位会自动用空格填充以达到8位的长度要求)</param>
        /// <param name="encoding">编码格式</param>
        public static bool EncryptFile(string sourceFilePath, string destinationFilePath, string encryptKey, Encoding encoding = null)
        {
            if (!File.Exists(sourceFilePath)) throw new Exception("文件不存在");
            if (string.IsNullOrWhiteSpace(encryptKey)) throw new Exception("密匙不能为空");

            encoding = encoding ?? DefaultEncoding;
            bool bRet = false;
            try
            {
                if (encryptKey.Length > 8) throw new Exception(InvalidDesKey);
                byte[] keyBytes = encoding.GetBytes(encryptKey.PadRight(8));
                byte[] keyIv = { 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF };

                using (FileStream fin = new FileStream(sourceFilePath, FileMode.Open, FileAccess.Read))
                {
                    using (FileStream fout = new FileStream(destinationFilePath, FileMode.OpenOrCreate, FileAccess.Write))
                    {
                        fout.SetLength(0);
                        //Create variables to help with read and write.
                        byte[] bin = new byte[100]; //This is intermediate storage for the encryption.
                        long rdlen = 0; //This is the total number of bytes written.
                        long totlen = fin.Length; //This is the total length of the input file.
                        int len; //This is the number of bytes to be written at a time.

                        using (DES des = new DESCryptoServiceProvider())
                        {
                            using (CryptoStream cs = new CryptoStream(fout, des.CreateEncryptor(keyBytes, keyIv), CryptoStreamMode.Write))
                            {
                                while (rdlen < totlen)
                                {
                                    len = fin.Read(bin, 0, bin.Length);
                                    cs.Write(bin, 0, len);
                                    rdlen += len;
                                }
                                cs.Close();
                            }
                        }

                        fout.Close();
                    }

                    fin.Close();
                }

                bRet = true;
            }
            catch
            {
                bRet = false;
            }
            return bRet;
        }
        /// <summary>
        /// DES解密文件
        /// </summary>
        /// <param name="sourceFilePath">待解密文件</param>
        /// <param name="destinationFilePath">解密后的文件保存路径</param>
        /// <param name="decryptKey">密钥(要求为8位，不足8位会自动用空格填充以达到8位的长度要求)</param>
        /// <param name="encoding">编码格式</param>
        public static bool DecryptFile(string sourceFilePath, string destinationFilePath, string decryptKey, Encoding encoding = null)
        {
            if (!File.Exists(sourceFilePath)) throw new Exception("文件不存在");
            if (string.IsNullOrWhiteSpace(decryptKey)) throw new Exception("密匙不能为空");

            encoding = encoding ?? DefaultEncoding;
            bool bRet = false;
            try
            {
                if (decryptKey.Length > 8) throw new Exception(InvalidDesKey);
                byte[] keyBytes = encoding.GetBytes(decryptKey.PadRight(8));
                byte[] keyIv = { 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF };

                using (FileStream fin = new FileStream(sourceFilePath, FileMode.Open, FileAccess.Read))
                {
                    using (FileStream fout = new FileStream(destinationFilePath, FileMode.OpenOrCreate, FileAccess.Write))
                    {
                        fout.SetLength(0);
                        //Create variables to help with read and write.
                        byte[] bin = new byte[100]; //This is intermediate storage for the encryption.
                        long rdlen = 0; //This is the total number of bytes written.
                        long totlen = fin.Length; //This is the total length of the input file.
                        int len; //This is the number of bytes to be written at a time.

                        using (DES des = new DESCryptoServiceProvider())
                        {
                            using (CryptoStream cs = new CryptoStream(fout, des.CreateDecryptor(keyBytes, keyIv), CryptoStreamMode.Write))
                            {
                                while (rdlen < totlen)
                                {
                                    len = fin.Read(bin, 0, bin.Length);
                                    cs.Write(bin, 0, len);
                                    rdlen += len;
                                }
                                cs.Close();
                            }
                        }

                        fout.Close();
                    }

                    fin.Close();
                }

                bRet = true;
            }
            catch
            {
                bRet = false;
            }
            return bRet;
        }
        #endregion

        #region 3DES
        /// <summary>
        /// 3DES加密(基于DES，对一块数据用三个不同的密钥进行三次加密，强度更高)
        /// </summary>
        /// <param name="content">待加密字符串</param>
        /// <param name="encryptKey1">密匙1</param>
        /// <param name="encryptKey2">密匙2</param>
        /// <param name="encryptKey3">密匙3</param>
        /// <param name="encodeMode">加密模式</param>
        /// <param name="encoding">编码格式</param>
        /// <returns></returns>
        public static string EncryptTriple(string content, string encryptKey1, string encryptKey2, string encryptKey3, EncodeMode encodeMode = EncodeMode.Base64, Encoding encoding = null)
        {
            if (string.IsNullOrWhiteSpace(content)) throw new Exception("加密内容不能为空");
            if (string.IsNullOrWhiteSpace(encryptKey1) || string.IsNullOrWhiteSpace(encryptKey2) || string.IsNullOrWhiteSpace(encryptKey3)) throw new Exception("加密密匙不能为空");

            string strEncrypt = Encrypt(content, encryptKey3, encodeMode, encoding);
            strEncrypt = Encrypt(strEncrypt, encryptKey2, encodeMode, encoding);
            strEncrypt = Encrypt(strEncrypt, encryptKey1, encodeMode, encoding);
            return strEncrypt;
        }
        /// <summary>
        /// 3DES解密(基于DES，对一块数据用三个不同的密钥进行三次加密，强度更高)
        /// </summary>
        /// <param name="content">待解密字符串</param>
        /// <param name="decryptKey1">密匙1</param>
        /// <param name="decryptKey2">密匙2</param>
        /// <param name="decryptKey3">密匙3</param>
        /// <param name="encodeMode">加密模式</param>
        /// <param name="encoding">编码格式</param>
        /// <returns></returns>
        public static string DecryptTriple(string content, string decryptKey1, string decryptKey2, string decryptKey3, EncodeMode encodeMode = EncodeMode.Base64, Encoding encoding = null)
        {
            if (string.IsNullOrWhiteSpace(content)) throw new Exception("解密内容不能为空");
            if (string.IsNullOrWhiteSpace(decryptKey1) || string.IsNullOrWhiteSpace(decryptKey2) || string.IsNullOrWhiteSpace(decryptKey3)) throw new Exception("解密密匙不能为空");

            string strDecrypt = Decrypt(content, decryptKey1, encodeMode, encoding);
            strDecrypt = Decrypt(strDecrypt, decryptKey2, encodeMode, encoding);
            strDecrypt = Decrypt(strDecrypt, decryptKey3, encodeMode, encoding);
            return strDecrypt;
        }
        #endregion
    }
}
