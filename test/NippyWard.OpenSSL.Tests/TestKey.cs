// Copyright (c) 2009-2011 Frank Laub
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
using System.Buffers;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.IO;

using Xunit;
using Xunit.Abstractions;

using NippyWard.OpenSSL.ASN1;
using NippyWard.OpenSSL.Keys;

namespace NippyWard.OpenSSL.Tests
{
	public class TestKey : TestBase
	{
        public static readonly IEnumerable<object[]> _EncryptionData = new List<object[]>
        {
            new object[] { "abc" },
            new object[] { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" },
        };

        public TestKey(ITestOutputHelper outputHelper)
            : base(outputHelper) { }

        protected override void Dispose(bool disposing) { }

        private static void EncryptDecrypt(Key key, string str)
        {
            ulong encryptedLength, decryptedLength;
            ReadOnlySpan<byte> unencrypted;
            Span<byte> encrypted, decrypted;
            byte[] encBuf, decBuf;
            KeyContext keyContext;

            unencrypted = MemoryMarshal.AsBytes(str.AsSpan());

            using (keyContext = key.CreateEncryptionContext())
            {
                //get size of encrypted buffer
                encryptedLength = key.EncryptedLength(in keyContext, unencrypted);
                Assert.NotEqual((uint)0, encryptedLength);

                //create buffer to store encrypted
                encBuf = new byte[encryptedLength];
                encrypted = new Span<byte>(encBuf);

                //encrypt buffer
                key.Encrypt(in keyContext, unencrypted, encrypted, out encryptedLength);
                encrypted = encrypted.Slice(0, (int)encryptedLength);
            }

            using (keyContext = key.CreateDecryptionContext())
            {
                //get size of decrypted buffer
                decryptedLength = key.DecryptedLength(in keyContext, encrypted);
                Assert.NotEqual((uint)0, encryptedLength);

                //create buffer to store decrypted
                decBuf = new byte[decryptedLength];
                decrypted = new Span<byte>(decBuf);

                //decrypt buffer
                key.Decrypt(in keyContext, encrypted, decrypted, out decryptedLength);
                Assert.Equal(unencrypted.Length, (int)decryptedLength);
                decrypted = decrypted.Slice(0, (int)decryptedLength);
            }

            Assert.True(unencrypted.SequenceEqual(decrypted));
        }

        [Fact]
		public void CanCompareRSA()
		{
			using (RSAKey lhs = new RSAKey(1024))
			{
				using (Key rhs = PrivateKey.GetCorrectKey(lhs._Handle))
				{
					Assert.Equal(lhs, rhs);

					using (RSAKey rsa2 = new RSAKey(1024))
					{
						Assert.NotEqual(lhs, rsa2);
					}
				}
			}
		}

        //only one supported bye EVP_PKEY_encrypt_init (???)
        [Theory]
        [MemberData(nameof(_EncryptionData))]
        public void TestRSAEncryptDecrypt(string str)
        {
            using (RSAKey key = new RSAKey(1024))
            {
                EncryptDecrypt(key, str);
            }
        }

		[Fact]
		public void CanCompareDSA()
		{
			using (DSAKey lhs = new DSAKey(1024))
            {
                using (Key rhs = PrivateKey.GetCorrectKey(lhs._Handle))
                {
                    Assert.Equal(lhs, rhs);

                    using(DSAKey dsa2 = new DSAKey(1024))
                    {
                        Assert.NotEqual(lhs, dsa2);
                    }
                }
            }
		}

        [Fact]
		public void CanCompareDH()
		{
            using (DHKey lhs = new DHKey(1024, 2))
            {
                using (Key rhs = PrivateKey.GetCorrectKey(lhs._Handle))
                {
                    Assert.Equal(lhs, rhs);

                    using (DHKey dsa2 = new DHKey(1024, 2))
                    {
                        Assert.NotEqual(lhs, dsa2);
                    }
                }
            }
		}

        [Fact]
		public void CanCompareEC()
		{
			using (ECKey lhs = new ECKey(ECCurveType.prime256v1))
			{
                using (Key rhs = PrivateKey.GetCorrectKey(lhs._Handle))
                {
                    Assert.Equal(lhs, rhs);

                    using (ECKey ec2 = new ECKey(ECCurveType.prime256v1))
                    {
                        Assert.NotEqual(lhs, ec2);
                    }
                }
            }
		}

        [Fact]
        public void CanSaveAsPEM()
        {
            using (RSAKey key = new RSAKey(1024))
            {
                using (MemoryStream ms = new MemoryStream())
                {
                    //TODO: verify
                    key.Write(ms, "", CipherType.NONE, FileEncoding.PEM);
                }
            }
        }

        [Fact]
        public void CanSaveAsDER()
        {
            using (RSAKey key = new RSAKey(1024))
            {
                using (MemoryStream ms = new MemoryStream())
                {
                    //TODO: verify
                    key.Write(ms, "", CipherType.NONE, FileEncoding.DER);
                }
            }
        }
    }
}
