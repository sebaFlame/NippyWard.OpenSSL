// Copyright (c) 2006-2007 Frank Laub
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
// 3. The name of the author may not be used to endorse or promote products
//    derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
// OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
// IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
// NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
// THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
using System;
using System.Text;

using Xunit;
using Xunit.Abstractions;

using OpenSSL.Core.Ciphers;
using OpenSSL.Core.ASN1;

namespace OpenSSL.Core.Tests
{
	public class TestAES : TestBase
	{
        public TestAES(ITestOutputHelper outputHelper)
            : base(outputHelper) { }

        [Fact]
		public void TestCase()
		{
			string magic = "Salted__";
			const int PKCS5_SALT_LEN = 8;
			string base64 = "U2FsdGVkX1/moDHvAjok9X4prr8TXQtv9LRAIHk1IE8=";
			byte[] input = Convert.FromBase64String(base64);
			byte[] salt = new byte[PKCS5_SALT_LEN];
			byte[] msg = new byte[input.Length - magic.Length - PKCS5_SALT_LEN];
			Buffer.BlockCopy(input, magic.Length, salt, 0, salt.Length);
			Buffer.BlockCopy(input, magic.Length + PKCS5_SALT_LEN, msg, 0, msg.Length);
            byte[] password = Encoding.ASCII.GetBytes("example");
            string text;

            byte[] decrypted;
            using (CipherDecryption cc = new CipherDecryption(CipherType.AES_256_CBC, DigestType.MD5, salt, password))
            {
                byte[] tempBuf = new byte[cc.GetMaximumOutputLength(msg.Length)];
                byte[] finalBuf = new byte[cc.GetCipherBlockSize()];

                Span<byte> msgSpan = new Span<byte>(msg);
                Span<byte> outputSpan = new Span<byte>(tempBuf);

                int decryptedLength = cc.Update(msgSpan, ref outputSpan);

                outputSpan = new Span<byte>(finalBuf);
                int finalDecryptedLength = cc.Finalize(ref outputSpan);

                decrypted = new byte[decryptedLength + finalDecryptedLength];
                Buffer.BlockCopy(tempBuf, 0, decrypted, 0, decryptedLength);
                Buffer.BlockCopy(finalBuf, 0, decrypted, decryptedLength, finalDecryptedLength);
            }

            text = Encoding.ASCII.GetString(decrypted, 0, decrypted.Length);
            Assert.Equal("Hello world!\n", text);
        }
	}
}

