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

using Xunit;
using OpenSSL.Core.Core;
using OpenSSL.Core.Crypto;
using OpenSSL.Core.Crypto.EC;

namespace OpenSSL.Core.Tests
{
	public class TestCryptoKey : TestBase
	{
		[Fact]
		public void CanCreateAndDispose()
		{
			using (new CryptoKey())
			{
			}
		}

		[Fact]
		public void CanCompareRSA()
		{
			using (var rsa = new RSA())
			{
				rsa.GenerateKeys(1024, BigNumber.One, null, null);
				using (var lhs = new CryptoKey(rsa))
				{
					Assert.Equal(lhs, lhs);
					using (var rhs = new CryptoKey(rsa))
					{
						Assert.Equal(lhs, rhs);
					}

					using (var rsa2 = new RSA())
					{
						rsa2.GenerateKeys(1024, BigNumber.One, null, null);
						using (var other = new CryptoKey(rsa2))
						{
							Assert.NotEqual(lhs, other);
						}
					}
				}
			}
		}

		[Fact]
		public void CanCompareDSA()
		{
			using (var dsa = new DSA(true))
			using (var lhs = new CryptoKey(dsa))
			{
				Assert.Equal(lhs, lhs);
				using (var rhs = new CryptoKey(dsa))
				{
					Assert.Equal(lhs, rhs);
				}

				using (var dsa2 = new DSA(true))
				using (var other = new CryptoKey(dsa2))
				{
					Assert.NotEqual(lhs, other);
				}
			}
		}

		[Fact]
		public void CanCompareDH()
		{
			using (var dh = new DH())
			{
				dh.GenerateKeys();

				using (var lhs = new CryptoKey(dh))
				{
					Assert.Equal(lhs, lhs);
					using (var rhs = new CryptoKey(dh))
					{
						Assert.Equal(lhs, rhs);
					}

					using (var dh2 = new DH(1, 5))
					{
						dh2.GenerateKeys();
						using (var other = new CryptoKey(dh2))
						{
							Assert.NotEqual(lhs, other);
						}
					}
				}
			}
		}

		[Fact]
		public void CanCompareEC()
		{
			using (var ec = Key.FromCurveName(Objects.NID.X9_62_prime256v1))
			{
				ec.GenerateKey();

				using (var lhs = new CryptoKey(ec))
				{
					Assert.Equal(lhs, lhs);
					using (var rhs = new CryptoKey(ec))
					{
						Assert.Equal(lhs, rhs);
					}

					using (var ec2 = Key.FromCurveName(Objects.NID.X9_62_prime256v1))
					{
						ec2.GenerateKey();

						using (var other = new CryptoKey(ec2))
						{
							Assert.NotEqual(lhs, other);
						}
					}
				}
			}
		}

		[Fact]
		public void CanCreateFromDSA()
		{
			using (var dsa = new DSA(true))
			{
				using (var key = new CryptoKey(dsa))
				{
					Assert.Equal(CryptoKey.KeyType.DSA, key.Type);
					Assert.Equal(dsa.Size, key.Size);
					Assert.Equal(dsa.Handle, key.GetDSA().Handle);
				}

				using (var key = new CryptoKey())
				{
					key.Assign(dsa);
					Assert.Equal(dsa.Handle, key.GetDSA().Handle);
				}
			}

			using (var key = new CryptoKey(new DSA(false)))
			{
				Assert.Equal(CryptoKey.KeyType.DSA, key.Type);
			}
		}

		[Fact]
		public void CanCreateFromRSA()
		{
			using (var rsa = new RSA())
			{
				rsa.GenerateKeys(1024, BigNumber.One, null, null);
				using (var key = new CryptoKey(rsa))
				{
					Assert.Equal(CryptoKey.KeyType.RSA, key.Type);
					Assert.Equal(rsa.Size, key.Size);
					Assert.Equal(rsa.Handle, key.GetRSA().Handle);
				}

				using (var key = new CryptoKey())
				{
					key.Assign(rsa);
					Assert.Equal(rsa.Handle, key.GetRSA().Handle);
				}
			}
		}

		[Fact]
		public void CanCreateFromEC()
		{
			using (var ec = new Key())
			{
				using (var group = Group.FromCurveName(Objects.NID.X9_62_prime256v1))
				{
					ec.Group = group;
				}
				ec.GenerateKey();
				using (var key = new CryptoKey(ec))
				{
					Assert.Equal(CryptoKey.KeyType.EC, key.Type);
					Assert.Equal(ec.Size, key.Size);
					Assert.Equal(ec.Handle, key.GetEC().Handle);
				}

				using (var key = new CryptoKey())
				{
					key.Assign(ec);
					Assert.Equal(ec.Handle, key.GetEC().Handle);
				}
			}
		}

		[Fact]
		public void CanCreateFromDH()
		{
			using (var dh = new DH())
			{
				dh.GenerateKeys();

				using (var key = new CryptoKey(dh))
				{
					Assert.Equal(CryptoKey.KeyType.DH, key.Type);
					Assert.Equal(dh.Handle, key.GetDH().Handle);
				}

				using (var key = new CryptoKey())
				{
					key.Assign(dh);
					Assert.Equal(dh.Handle, key.GetDH().Handle);
				}
			}
		}
	}
}
