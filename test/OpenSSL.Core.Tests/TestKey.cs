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
using Xunit.Abstractions;

using OpenSSL.Core.ASN1;
using OpenSSL.Core.Keys;

namespace OpenSSL.Core.Tests
{
    //TODO: add encryption/decryption
	public class TestKey : TestBase
	{
        public TestKey(ITestOutputHelper outputHelper)
            : base(outputHelper) { }

        /* MEMORY
         * leaks error strings on first RSA key generation
        */
        [Fact]
		public void CanCompareRSA()
		{
			using (RSAKey lhs = new RSAKey(1024))
			{
				lhs.GenerateKey();
				using (Key rhs = PrivateKey.GetCorrectKey(lhs.KeyHandle))
				{
					Assert.Equal(lhs, rhs);

					using (RSAKey rsa2 = new RSAKey(1024))
					{
						rsa2.GenerateKey();
						Assert.NotEqual(lhs, rsa2);
					}
				}
			}
		}

		[Fact]
		public void CanCompareDSA()
		{
			using (DSAKey lhs = new DSAKey(1024))
            {
                lhs.GenerateKey();
                using (Key rhs = PrivateKey.GetCorrectKey(lhs.KeyHandle))
                {
                    Assert.Equal(lhs, rhs);

                    using(DSAKey dsa2 = new DSAKey(1024))
                    {
                        dsa2.GenerateKey();
                        Assert.NotEqual(lhs, dsa2);
                    }
                }
            }
		}

		[Fact]
		public void CanCompareDH()
		{
            using (DHKey lhs = new DHKey(32, 2))
            {
                lhs.GenerateKey();
                using (Key rhs = PrivateKey.GetCorrectKey(lhs.KeyHandle))
                {
                    Assert.Equal(lhs, rhs);

                    using (DHKey dsa2 = new DHKey(32, 2))
                    {
                        dsa2.GenerateKey();
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
				lhs.GenerateKey();

                using (Key rhs = PrivateKey.GetCorrectKey(lhs.KeyHandle))
                {
                    Assert.Equal(lhs, rhs);

                    using (ECKey ec2 = new ECKey(ECCurveType.prime256v1))
                    {
                        ec2.GenerateKey();
                        Assert.NotEqual(lhs, ec2);
                    }
                }
            }
		}
	}
}
