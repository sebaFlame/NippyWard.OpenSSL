using System;
using Xunit;
using OpenSSL.Core.Crypto;
using System.Text;
using System.Reflection;
using OpenSSL.Core.Core;
using System.Collections.Generic;
using System.Collections;
using System.Linq;

namespace OpenSSL.Core.Tests
{
	public class TestCipher
	{
		static CryptoKey[] Keys;

		static TestCipher()
		{
			const int numKeys = 10;
			Keys = new CryptoKey[numKeys];
			for (int i = 0; i < numKeys; i++)
			{
				using (var rsa = new RSA())
				{
					rsa.GenerateKeys(1024, BigNumber.One, null, null);
					Keys[i] = new CryptoKey(rsa);
				}
			}
		}

		public static class WithNullFactory
        {
            public static IEnumerable<object[]> GetEnumerator()
            {
				var fields = typeof(Cipher).GetFields(BindingFlags.Public | BindingFlags.Static);
                return fields
                    .Where(x => x.Name != "DES_EDE3_CFB1")
                    .Select(x => new[] { x.GetValue(null) });
			}
        }

		public static class Factory
		{
			public static IEnumerable<object[]> GetEnumerator()
			{
				var fields = typeof(Cipher).GetFields(BindingFlags.Public | BindingFlags.Static);
                return fields
                    .Where(x => x.Name != "Null")
                    .Where(x => x.Name != "DES_EDE3_CFB1")
                    .Select(x => new[] { x.GetValue(null) });
			}
		}

		[Theory]
		[MemberData(nameof(WithNullFactory.GetEnumerator), MemberType = typeof(WithNullFactory))]
		public void TestEncryptDecrypt(Cipher cipher)
		{
			var inputMsg = "This is a message";
			var input = Encoding.ASCII.GetBytes(inputMsg);
			var iv = Encoding.ASCII.GetBytes("12345678");
			var key = Encoding.ASCII.GetBytes("This is the key");

			Console.Write("Using cipher {0}: ", cipher.LongName);
			using (var cc = new CipherContext(cipher))
			{
				Console.Write(" KeyLength: {0}, IVLength: {1}, BlockSize: {2}, Stream: {3} ",
					cipher.KeyLength, cipher.IVLength, cipher.BlockSize, cc.IsStream);

				var pt = cc.Encrypt(input, key, iv);
				if (cipher == Cipher.Null)
					Assert.Equal(input, pt);
				else
					Assert.NotEqual(input, pt);

				var ct = cc.Decrypt(pt, key, iv);
				var msg = Encoding.ASCII.GetString(ct);
				Console.WriteLine("\"{0}\"", msg);
				Assert.Equal(inputMsg, msg);
			}
		}

		[Theory]
        [MemberData(nameof(Factory.GetEnumerator), MemberType = typeof(Factory))]
        public void TestEncryptDecryptWithSalt(Cipher cipher)
		{
            if (cipher == Cipher.Null)
                return;

			var inputMsg = "This is a message";
			var input = Encoding.ASCII.GetBytes(inputMsg);
			var salt = Encoding.ASCII.GetBytes("salt");
			var secret = Encoding.ASCII.GetBytes("Password!");

			Console.Write("Using cipher {0}: ", cipher.LongName);
			using (var cc = new CipherContext(cipher))
			{
				Console.Write(" KeyLength: {0}, IVLength: {1}, BlockSize: {2}, Stream: {3} ",
					cipher.KeyLength, cipher.IVLength, cipher.BlockSize, cc.IsStream);
				byte[] iv;
				var key = cc.BytesToKey(MessageDigest.SHA1, salt, secret, 1, out iv);

				var pt = cc.Encrypt(input, key, iv);
				Assert.NotEqual(input, pt);

				var ct = cc.Decrypt(pt, key, iv);
				var msg = Encoding.ASCII.GetString(ct);
				Console.WriteLine("\"{0}\"", msg);
				Assert.Equal(inputMsg, msg);
			}
		}

		[Theory]
        [MemberData(nameof(Factory.GetEnumerator), MemberType = typeof(Factory))]
        public void TestSealOpen(Cipher cipher)
		{
            if (cipher == Cipher.Null)
                return;

			var inputMsg = "This is a message";
			var input = Encoding.ASCII.GetBytes(inputMsg);

			using (var cc = new CipherContext(cipher))
			{
				var env = cc.Seal(Keys, input);
				Assert.NotEqual(input, env.Data);

				for (int i = 0; i < Keys.Length; i++)
				{
					var result = cc.Open(env.Data, env.Keys[i], env.IV, Keys[i]);
					Assert.Equal(input, result);
				}
			}
		}
	}
}


