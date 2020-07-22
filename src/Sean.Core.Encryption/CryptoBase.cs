using System.Text;

namespace Sean.Core.Encryption
{
    /// <summary>
    /// 加解密抽象基类
    /// </summary>
    public abstract class CryptoBase
    {
        /// <summary>
        /// 默认编码格式为UTF8（注：ASCII会出现中文乱码）
        /// </summary>
        public static readonly Encoding DefaultEncoding = Encoding.UTF8;
    }
}
