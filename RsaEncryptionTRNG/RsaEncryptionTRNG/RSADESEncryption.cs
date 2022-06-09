using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Serialization;

namespace RsaEncryptionTRNG
{
    internal class RSADESEncryption
    {
        byte[]? DesKey;
        byte[]? DesIV;

        const int minRange = 1000000;
        const int RSAKEYLENGTH = 2048;


        RSAParameters RSAPublicKey;
        RSAParameters RSAPrivateKey;
        private static RSACryptoServiceProvider RSA = new RSACryptoServiceProvider(RSAKEYLENGTH);
        public RSADESEncryption(byte[] rsaKeysData)
        {
            
            //creating rsa pair keys with random data

            creatingRSAKeys(rsaKeysData);
        }


        private void creatingRSAKeys(byte[] rsaKeysData)
        {
            
            RSAPrivateKey = RSA.ExportParameters(true);
            RSAPublicKey = RSA.ExportParameters(false);



            //var primes = Enumerable.Range(minRange, int.MaxValue - 1).Where(num => num.isPrime());


            //creating p and q - 1024
            int twoNumbers = 0;
            BigInteger[] pq = new BigInteger[2]; // p, q
            for(int i = 0;i<rsaKeysData.Length - RSAKEYLENGTH; i++)
            {
                var key = rsaKeysData.Skip(i).Take(RSAKEYLENGTH / (sizeof(byte) * 8 * 2)).ToArray();

                BigInteger bigInteger = new BigInteger(key);

                var temp = RSA.LegalKeySizes;
                if (
                    //bigInteger.isPrime()
                    bigInteger.IsProbablyPrime()
                    )
                {
                    pq[twoNumbers++] = bigInteger;

                    if (twoNumbers == 2) break;
                }

                var debug = 1;
            }

            BigInteger n = pq[0] * pq[1];
            BigInteger phi = (pq[0] - 1) * (pq[1] - 1);
            BigInteger e;
            List<BigInteger> exponentList = new List<BigInteger>();
            Random random = new Random();


            for(BigInteger i = 300; i < 1_000_000; i++)
            {
                var gcd = ExtensionClass.euclid(phi, i);
                if (gcd.IsOne) exponentList.Add(i);
            }
            BigInteger d;
            (BigInteger, BigInteger) secret;
            do
            {
                e = exponentList[random.Next() % exponentList.Count];
                secret = ExtensionClass.exteuclid(phi, e);

            } while (!secret.Item1.IsOne);
            d = secret.Item2;


            var inverseQ = ExtensionClass.exteuclid(pq[0], pq[1]).Item2;
            //var DP = ExtensionClass.exteuclid(d, pq[0]).Item2;
            //var DQ = ExtensionClass.exteuclid(d, pq[1]).Item2;
            //var DP2 = ExtensionClass.exteuclid(pq[0], d);
            //var DQ2 = ExtensionClass.exteuclid(pq[1], d);


            //adding calculated values to RSA keys

            RSAParameters publicKey = new RSAParameters();
            publicKey.Modulus = n.BigIntegerToRSAByteArray();
            publicKey.Exponent = e.BigIntegerToRSAByteArray();


            RSAParameters privateKey = new RSAParameters();
            privateKey.Modulus = n.BigIntegerToRSAByteArray();
            privateKey.D = d.BigIntegerToRSAByteArray();
            privateKey.Exponent = e.BigIntegerToRSAByteArray();
            privateKey.P = pq[0].BigIntegerToRSAByteArray();
            privateKey.Q = pq[1].BigIntegerToRSAByteArray();
            privateKey.DP = (d % (pq[0] - 1)).BigIntegerToRSAByteArray();
            privateKey.DQ = (d % (pq[1] - 1)).BigIntegerToRSAByteArray();
            privateKey.InverseQ = inverseQ.BigIntegerToRSAByteArray();

            RSAPublicKey = publicKey;
            RSAPrivateKey = privateKey;

            var debug2 = 2;


        }


        public bool isSignatureVerified(string dataToVerify)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(dataToVerify);
            byte[]? signedBytes;

            //signing with private key
            signedBytes = RSAHashAndSign(bytes, RSAPrivateKey);


            return VerifySign(bytes, signedBytes, RSAPublicKey);
        }

        private bool VerifySign(byte[] bytes, byte[] signedBytes, RSAParameters RSAKey)
        {
            RSACryptoServiceProvider RSAalg = new RSACryptoServiceProvider();
            RSAalg.ImportParameters(RSAKey);
            return RSAalg.VerifyData(bytes, SHA256.Create(), signedBytes);

        }

        private byte[]? RSAHashAndSign(byte[] bytes, RSAParameters RSAKey)
        {
            try
            {
                RSACryptoServiceProvider RSAalg = new RSACryptoServiceProvider();
                RSAalg.ImportParameters(RSAKey);
                return RSAalg.SignData(bytes, SHA256.Create());
            }
            catch (CryptographicException e)
            {
                Console.WriteLine(e.Message);
                return null;
            }
        }

        public string PublicKey()
        {
            StringWriter sw = new();
            XmlSerializer xs = new(typeof(RSAParameters));
            xs.Serialize(sw, RSAPublicKey);
            return sw.ToString();
        }

        public string PrivateKey()
        {
            StringWriter sw = new();
            XmlSerializer xs = new(typeof(RSAParameters));
            xs.Serialize(sw, RSAPrivateKey);
            return sw.ToString();
        }


        public byte[] Encrypt(string plainText)
        {

            //adding public key to rsa provider
            RSA = new RSACryptoServiceProvider(2048);
            RSA.ImportParameters(RSAPublicKey);


            //encrypt with public key
            var plainByteArray = Encoding.UTF8.GetBytes(plainText);
            var RSACypher = RSA.Encrypt(plainByteArray, false);


            //encrypt with des
            DES des = DES.Create();
            des.Padding = PaddingMode.None;
            DesIV = des.IV;
            DesKey = des.Key;

            using (MemoryStream stream = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(stream, des.CreateEncryptor(DesKey, DesIV), CryptoStreamMode.Write))
                {
                    cs.Write(RSACypher, 0, RSACypher.Length);
                    return stream.ToArray();
                }
            }
        }

        public string Decrypt(byte[] cypherText)
        {
            //decrypt with des parameters
            byte[] DESDecrypt;
            DES des = DES.Create();
            des.Padding = PaddingMode.None;
            using (MemoryStream stream = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(stream, des.CreateDecryptor(DesKey!, DesIV!), CryptoStreamMode.Write))
                {
                    
                    cs.Write(cypherText);
                    DESDecrypt = stream.ToArray();
                }
            }

            //decrypt with rsa algorithm with private key
            RSA.ImportParameters(RSAPrivateKey);

            var plainArray = RSA.Decrypt(DESDecrypt, false);
            
            return Encoding.UTF8.GetString(plainArray);
        }





        public static string getStringFromByteArray(byte[] arr)
        {
            var temp = System.Text.Encoding.UTF8.GetString(arr);
            return temp;
        }

    }
}
