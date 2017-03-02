using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace DotNetTestConsole
{
    class Program
    {
        static void Main(string[] args)
        {
            string key = "";
            var text = "Hello World";

            Console.WriteLine(text);
            string encryptText = EncryptText(text, key);
            Console.WriteLine(encryptText);

            Console.WriteLine(DecryptText(encryptText, key));
        }

        private static readonly CipherMode cipherMode = CipherMode.CBC;
        private static readonly int blockSize = 128;

        public static string EncryptText(string text, string key)
        {
            string[] aesKeyAndIV = key.Split('|');
            if (aesKeyAndIV.Length != 2) return string.Empty;

            byte[] aesKey = FromHexString(aesKeyAndIV[0]);
            byte[] aesIV = Encoding.UTF8.GetBytes(aesKeyAndIV[1]);
            string result = Convert.ToBase64String(EncryptStringToBytes_Aes(text, aesKey, aesIV));
            return result;
        }

        public static string DecryptText(string text, string key)
        {
            string[] aesKeyAndIV = key.Split('|');
            if (aesKeyAndIV.Length != 2) return string.Empty;

            byte[] aesKey = FromHexString(aesKeyAndIV[0]);
            byte[] aesIV = Encoding.UTF8.GetBytes(aesKeyAndIV[1]);
            string result = DecryptStringFromBytes_Aes(Convert.FromBase64String(text), aesKey, aesIV);
            return result;
        }

        private static byte[] FromHexString(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                     .Where(x => x % 2 == 0)
                     .Select(x => byte.Parse(hex.Substring(x, 2), System.Globalization.NumberStyles.AllowHexSpecifier))
                     .ToArray();
        }

        private static byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encrypted;
            // Create an AesCryptoServiceProvider object
            // with the specified key and IV.
            using (AesCryptoServiceProvider aesAlg = new AesCryptoServiceProvider())
            {
                aesAlg.Mode = cipherMode;
                aesAlg.BlockSize = blockSize;
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create a decrytor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            // Return the encrypted bytes from the memory stream.
            return encrypted;
        }

        private static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;
            // Create an AesCryptoServiceProvider object
            // with the specified key and IV.
            using (AesCryptoServiceProvider aesAlg = new AesCryptoServiceProvider())
            {
                aesAlg.Mode = cipherMode;
                aesAlg.BlockSize = blockSize;
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create a decrytor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
            return plaintext;
        }
    }
}
