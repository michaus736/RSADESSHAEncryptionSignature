using RNG;
using RsaEncryptionTRNG;
using System.Security.Cryptography;
using System.Text;

Console.WriteLine("Starting");
string plainText = "Nadchodzi czas, kiedy będzie trzeba wybrać między tym co dobre, a tym co łatwe.";
//string plainText = "1233";


PostProcessingRNG RNG = new PostProcessingRNG();
var keyData = RNG.GetRandomData();


RSADESEncryption encryption = new RSADESEncryption(keyData);
var cipher = encryption.Encrypt(plainText);
var cipherText = RSADESEncryption.getStringFromByteArray(cipher);
var decryptedText = encryption.Decrypt(cipher);

Console.WriteLine($"RSA public key: {encryption.PublicKey()}");
Console.WriteLine($"RSA private key: {encryption.PrivateKey()}");
Console.WriteLine();
Console.WriteLine();


Console.WriteLine($"plain text: {plainText}");
Console.WriteLine($"cipher text: {cipherText}");
Console.WriteLine($"decrypted text: {decryptedText}");
Console.WriteLine("Ending");




Console.WriteLine("Signature verifying");

var isverified = encryption.isSignatureVerified(plainText);
var plainarr = Encoding.UTF8.GetBytes(plainText);

var a = new Org.BouncyCastle.Crypto.Digests.Sha3Digest(512);
a.BlockUpdate(plainarr, 0, plainarr.Length);

var sha3hash = new byte[512 / 8];
a.DoFinal(sha3hash, 0);

Console.WriteLine($"plain signature: {plainText}");
Console.WriteLine($"hashed signature SHA256: {Encoding.UTF8.GetString(SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(plainText)))}");
Console.WriteLine($"hashed signature SHA3-512: {Encoding.UTF8.GetString(sha3hash)}");
Console.WriteLine((isverified)?$"signature verified successfully":"$signature invalid");
