using System;
using System.Text;
using Sean.Core.Encryption.Enums;
using Sean.Utility.Format;

namespace Sean.Core.Encryption.Extensions
{
    /// <summary>
    /// 枚举扩展方法
    /// </summary>
    public static class EnumExtensions
    {
        #region EncodeMode
        /// <summary>
        /// 编码
        /// </summary>
        /// <param name="encodeMode"></param>
        /// <param name="data"></param>
        /// <param name="encoding"></param>
        /// <returns></returns>
        public static string EncodeToString(this EncodeMode encodeMode, string data, Encoding encoding)
        {
            switch (encodeMode)
            {
                case EncodeMode.None:
                    return data;
                case EncodeMode.Base64:
                    return Base64CryptoProvider.Encrypt(data);
                case EncodeMode.Hex:
                    return ConvertHelper.ToHexString(data, encoding);
                case EncodeMode.Base64ToHex:
                    return ConvertHelper.ToHexString(Base64CryptoProvider.Encrypt(data), encoding);
                default:
                    throw new NotSupportedException($"{string.Format(Constants.NotSupportedEncodeMode2, encodeMode.ToString())}");
            }
        }
        /// <summary>
        /// 编码
        /// </summary>
        /// <param name="encodeMode"></param>
        /// <param name="data"></param>
        /// <param name="encoding"></param>
        /// <returns></returns>
        public static string EncodeToString(this EncodeMode encodeMode, byte[] data, Encoding encoding)
        {
            switch (encodeMode)
            {
                //case EncodeMode.None:
                case EncodeMode.Base64:
                    return Base64CryptoProvider.EncryptFromByte(data);
                case EncodeMode.Hex:
                    return ConvertHelper.ToHexString(data, string.Empty);
                case EncodeMode.Base64ToHex:
                    return ConvertHelper.ToHexString(Base64CryptoProvider.EncryptFromByte(data), encoding);
                default:
                    throw new NotSupportedException($"{string.Format(Constants.NotSupportedEncodeMode2, encodeMode.ToString())}");
            }
        }

        /// <summary>
        /// 解码
        /// </summary>
        /// <param name="encodeMode"></param>
        /// <param name="data"></param>
        /// <param name="encoding"></param>
        /// <returns></returns>
        public static string DecodeToString(this EncodeMode encodeMode, string data, Encoding encoding)
        {
            switch (encodeMode)
            {
                case EncodeMode.None:
                    return data;
                case EncodeMode.Base64:
                    return Base64CryptoProvider.Decrypt(data, encoding);
                case EncodeMode.Hex:
                    return ConvertHelper.FromHexString(data, encoding);
                case EncodeMode.Base64ToHex:
                    return Base64CryptoProvider.Decrypt(ConvertHelper.FromHexString(data, encoding));
                default:
                    throw new NotSupportedException($"{string.Format(Constants.NotSupportedEncodeMode2, encodeMode.ToString())}");
            }
        }

        /// <summary>
        /// 解码
        /// </summary>
        /// <param name="encodeMode"></param>
        /// <param name="data"></param>
        /// <param name="encoding"></param>
        /// <returns></returns>
        public static byte[] DecodeToBytes(this EncodeMode encodeMode, string data, Encoding encoding)
        {
            switch (encodeMode)
            {
                //case EncodeMode.None:
                case EncodeMode.Base64:
                    return Base64CryptoProvider.DecryptToByte(data);
                case EncodeMode.Hex:
                    return ConvertHelper.ToBytes(data, string.Empty);
                case EncodeMode.Base64ToHex:
                    return Base64CryptoProvider.DecryptToByte(ConvertHelper.FromHexString(data, encoding));
                default:
                    throw new NotSupportedException($"{string.Format(Constants.NotSupportedEncodeMode2, encodeMode.ToString())}");
            }
        }
        #endregion
    }
}
