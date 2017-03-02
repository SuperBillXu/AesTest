using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace DotNetCoreTestConsole
{
    public class Program
    {
        private static readonly CipherMode cipherMode = CipherMode.CBC;
        private static readonly int blockSize = 128;

        public static void Main(string[] args)
        {
            string key = "";
            var text = "Hello World";

            Console.WriteLine(text);
            string encryptText = EncryptText(text, key);
            Console.WriteLine(encryptText);

            Console.WriteLine(DecryptText(encryptText, key));
        }

        public static string EncryptText(string text, string key)
        {
            string[] aesKeyAndIV = key.Split('|');
            if (aesKeyAndIV.Length != 2) return string.Empty;

            byte[] aesKey = FromHexString(aesKeyAndIV[0]);
            byte[] aesIV = Encoding.UTF8.GetBytes(aesKeyAndIV[1]);
            string result = EncryptText(text, aesKey, aesIV);
            return result;
        }

        public static string DecryptText(string text, string key)
        {
            string[] aesKeyAndIV = key.Split('|');
            if (aesKeyAndIV.Length != 2) return string.Empty;

            byte[] aesKey = FromHexString(aesKeyAndIV[0]);
            byte[] aesIV = Encoding.UTF8.GetBytes(aesKeyAndIV[1]);
            string result = DecryptText(text, aesKey, aesIV);
            return result;
        }

        private static byte[] FromHexString(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                     .Where(x => x % 2 == 0)
                     .Select(x => byte.Parse(hex.Substring(x, 2), System.Globalization.NumberStyles.AllowHexSpecifier))
                     .ToArray();
        }

        private static string EncryptText(string text, byte[] iv, byte[] keyAes)
        {
            string encryptText;
            using (var aes = Aes.Create())
            {
                aes.BlockSize = blockSize;
                aes.Mode = cipherMode;
                aes.Key = keyAes;
                aes.IV = iv;


                using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                using (var resultStream = new MemoryStream())
                {
                    var buffer = Encoding.UTF8.GetBytes(text);
                    using (var aesStream = new CryptoStream(resultStream, encryptor, CryptoStreamMode.Write))
                    using (var plainStream = new MemoryStream(buffer))
                    {
                        plainStream.CopyTo(aesStream);
                    }

                    var tempResult = resultStream.ToArray();
                    encryptText = Convert.ToBase64String(tempResult);
                }
            }
            return encryptText;
        }

        private static string DecryptText(string text, byte[] iv, byte[] keyAes)
        {
            string decryptText;
            using (var aes = Aes.Create())
            {
                aes.BlockSize = blockSize;
                aes.Mode = cipherMode;
                aes.Key = keyAes;
                aes.IV = iv;

                byte[] base64Bytes = Convert.FromBase64String(text);
                using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                using (var resultStream = new MemoryStream())
                {
                    using (var aesStream = new CryptoStream(resultStream, decryptor, CryptoStreamMode.Write))
                    using (var plainStream = new MemoryStream(base64Bytes))
                    {
                        plainStream.CopyTo(aesStream);
                    }

                    base64Bytes = resultStream.ToArray();
                    decryptText = Encoding.UTF8.GetString(base64Bytes);
                }
            }
            return decryptText;
        }

        private static byte[] GetRandomData(int bits)
        {
            var result = new byte[bits / 8];
            RandomNumberGenerator.Create().GetBytes(result);
            return result;
        }
    }
}
