using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace CryptoTest
{
    class Program
    {
        static void Main(string[] args)
        {

            var hmac = new HMACSHA256();
            var hmacBase64 = Convert.ToBase64String(hmac.Key);

            foreach (Byte b in hmac.Key)
                Console.Write($"{b} ");

            Console.WriteLine("\nhmac Key chars:");
            foreach (Byte b in hmac.Key)
            {
                Console.Write($"{(char)(b)}");
            }

            /*
            Byte[] singlebyte = { 128, 127 }; 
            Console.WriteLine($"\n\n { (char)128 } \n\n");
            Console.WriteLine($"\n\n { Encoding.ASCII.GetChars(singlebyte)[0]}  \n\n");
            */

            Console.WriteLine($"\n\n");
            Console.WriteLine($"Hash: {hmac.HashName} {hmac.Hash} {hmac.Key} \n");
            Console.WriteLine($"B64 Hash:          {hmacBase64}");
            Console.WriteLine($"B64 Url Safe Hash: {Base64UrlEncoder.Encode(hmac.Key)} \n\n");

            // ----------------------

            var key = new Byte[] { 123, 156 };
            var hmac2 = new HMACSHA256(key);

            // -------------------------

            // Create plain text secret and message
            var secret = "below is a free online tool that can be used to generate HMAC authentication code. We can generate hmac-sha256 as well as hmac-sha512 code with it";
            var msg = "a secret key known as a cryptographic key. HMAC is more secure than any other authentication codes as it contains Hashing as well as MAC";


            var key2 = Encoding.ASCII.GetBytes(secret);
            var msgbytes = Encoding.ASCII.GetBytes(msg);

            Console.WriteLine($"secret len: {secret.Length}    msg len: {msg.Length}");

            Console.WriteLine("secret: ");
            foreach (Byte b in key2)
                Console.Write($"{b} ");

            Console.WriteLine("\n\nsecret:");
            foreach (Byte b in key2)
                Console.Write($"{(char)(b)}");
            Console.WriteLine("\n");

            // Compute message hash using key
            var hmac3 = new HMACSHA256(key2);
            hmac3.Initialize();
            var hash1 = hmac3.ComputeHash(msgbytes);

            Console.WriteLine("Hash1 bytes:");
            foreach (Byte b in hash1)
                Console.Write($"{b} ");
            Console.WriteLine("\n");

            Console.WriteLine("Hash1 chars:");
            foreach (Byte b in hash1)
                Console.Write($"{(char)(b)}");

            Console.WriteLine("\n");
            Console.WriteLine($"B16 Hash: {ByteArrayToString(hash1)}");
            Console.WriteLine($"B64 Hash: {Convert.ToBase64String(hash1)}");

            hmac.Initialize();
            var hash2 = hmac.ComputeHash(msgbytes);

            Console.WriteLine("\n");
            Console.WriteLine($"B16 Hash: {ByteArrayToString(hash2)}");
            Console.WriteLine($"B64 Hash:          {Convert.ToBase64String(hash2)}");
            Console.WriteLine($"B64 Url Safe Hash: {Base64UrlEncoder.Encode(hash2)}");

            Console.WriteLine("\n");
            Console.WriteLine($"B16 Hash: {ByteArrayToString(key2)}");
            Console.WriteLine($"B64 Hash: {Convert.ToBase64String(key2)}");

            /*
            // Random junk
            object[] arr = { 10.20, 1, 1.2f, 1.4, 10L, 12 };
            using (MemoryStream ms = new MemoryStream())
            {
                foreach (dynamic t in arr)
                {
                    byte[] bytes = BitConverter.GetBytes(t);
                    ms.Write(bytes, 0, bytes.Length);
                }
                byte[] arr2 = ms.ToArray();
                foreach (Byte b in arr2)
                    Console.Write($"{(b)} ");
            }
            */
            
            // Note these come from the Azure SDK Nuget Package
            SymmetricSecurityKey test = new SymmetricSecurityKey(new byte[] {11} );
            TokenValidationParameters p = new TokenValidationParameters() {};
            SecurityTokenDescriptor d = new SecurityTokenDescriptor() { };
        }

        public static string ByteArrayToString(byte[] ba)
        {
            return BitConverter.ToString(ba).Replace("-", "").ToLower();
        }
    }
}
