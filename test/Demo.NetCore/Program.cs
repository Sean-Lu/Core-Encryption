using System;
using Sean.Core.Encryption;
using Sean.Core.Encryption.Enums;

namespace Demo.NetCore
{
    class Program
    {
        static void Main(string[] args)
        {
            RSACryptoByOpenSslProvider.GenerateXmlKey(out var publicKey, out var privateKey, encodeMode: EncodeMode.Hex);
            //Console.WriteLine($"公钥：{publicKey}");
            //Console.WriteLine($"密钥：{privateKey}");

            var rsaCryptoByOpenSslProvider = new RSACryptoByOpenSslProvider(RSAType.RSA, publicKey, privateKey, defaultDataEncodeMode: EncodeMode.Hex, defaultKeyEncodeMode: EncodeMode.Hex, isKeyFromXmlString: true);

            var content = "test123...";
            Console.WriteLine($"原始数据：{content}");

            var encrypt = rsaCryptoByOpenSslProvider.Encrypt(content);
            Console.WriteLine($"RSA非对称加密后：{encrypt}");

            var decrypt = rsaCryptoByOpenSslProvider.Decrypt(encrypt);
            Console.WriteLine($"RSA非对称解密后：{decrypt}");

            Console.ReadLine();
        }
    }
}
