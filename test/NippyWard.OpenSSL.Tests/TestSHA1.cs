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
using System.Collections.Generic;

using Xunit;
using Xunit.Abstractions;

using NippyWard.OpenSSL.ASN1;
using NippyWard.OpenSSL.Digests;

namespace NippyWard.OpenSSL.Tests
{
	public class TestSHA1 : TestBase
	{
		readonly string[] tests = {
			"abc",
			"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
		};

		readonly string[] results = {
			"A9-99-3E-36-47-06-81-6A-BA-3E-25-71-78-50-C2-6C-9C-D0-D8-9D",
			"84-98-3E-44-1C-3B-D2-6E-BA-AE-4A-A1-F9-51-29-E5-E5-46-70-F1",
		};

		const string bigret = "34-AA-97-3C-D4-C4-DA-A4-F6-1E-EB-2B-DB-AD-27-31-65-34-01-6F";

        public TestSHA1(ITestOutputHelper outputHelper)
            : base(outputHelper) { }

        protected override void Dispose(bool disposing) { }

        [Fact]
        public void TestDigestList()
        {
            HashSet<string> lstDigests = Digest.SupportedDigests;
            Assert.NotNull(lstDigests);
            Assert.NotEmpty(lstDigests);
        }

        [Fact]
        public void TestSingleUpdate()
        {
            Digest ctx;
            for (int i = 0; i < tests.Length; i++)
            {
                byte[] msg, hash;
                Span<byte> digest;
                string res;
                using (ctx = new Digest(DigestType.SHA1))
                {
                    msg = Encoding.ASCII.GetBytes(this.tests[i]);
                    ctx.Update(new Span<byte>(msg));
                    ctx.Finalize(out digest);

                    hash = digest.ToArray();
                    res = BitConverter.ToString(hash);
                    Assert.Equal(results[i], res);
                }
            }
        }

        //TODO: fails at random on release builds
        [Fact]
        public void TestMultipleUpdate()
        {
            byte[] buf = Encoding.ASCII.GetBytes(new string('a', 1000));
            using (Digest ctx = new Digest(DigestType.SHA1))
            {
                for (int i = 0; i < 1000; i++)
                    ctx.Update(buf);

                ctx.Finalize(out Span<byte> digest);

                byte[] retx = digest.ToArray();
                string strx = BitConverter.ToString(retx);
                Assert.Equal(bigret, strx);
            }
        }
    }
}
