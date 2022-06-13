﻿// Copyright (c) 2006-2008 Frank Laub
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
using System.Collections.Generic;
using System.Text;
using System.IO;
using OpenSSL;
using OpenSSL.Core.Core;
using OpenSSL.Core.Crypto;
using OpenSSL.Core.X509;
using Xunit;

namespace OpenSSL.Core.Tests
{
	public class TestX509 : TestBase
	{
		[Fact]
		public void TestDefaultDSA()
		{
			using (var cfg = new Configuration("openssl.cnf"))
			{
				// Test default DSA method
				using (var root = X509CertificateAuthority.SelfSigned(
					                  cfg,
					                  new SimpleSerialNumber(),
					                  "Root1",
					                  DateTime.Now,
					                  TimeSpan.FromDays(365)))
				{
					Console.WriteLine(root.Certificate);
				}
			}
		}

		[Fact]
		public void TestRsaSha1()
		{
			using (Configuration cfg = new Configuration("openssl.cnf"))
			{
				// Test RSA/SHA1 with other SelfSigned method
				BigNumber bn = 0x10001;
				CryptoKey key;

				using (RSA rsa = new RSA())
				{
					rsa.GenerateKeys(2048, bn, OnGenerator, null);
					key = new CryptoKey(rsa);
					// rsa is assigned, we no longer need this instance
				}

				using (var root = X509CertificateAuthority.SelfSigned(
					                  cfg,
					                  new SimpleSerialNumber(),
					                  key,
					                  MessageDigest.SHA1,
					                  "Root1",
					                  DateTime.Now,
					                  TimeSpan.FromDays(365)))
				{
					Console.WriteLine(root.Certificate);
				}
			}
		}

		[Fact]
		public void TestWithoutCfg()
		{
			BigNumber bn = 0x10001;
			CryptoKey key;
			using (RSA rsa = new RSA())
			{
				rsa.GenerateKeys(2048, bn, OnGenerator, null);
				key = new CryptoKey(rsa);
				// rsa is assigned, we no longer need this instance
			}

			var extList = new List<X509V3ExtensionValue> {
				new X509V3ExtensionValue("subjectKeyIdentifier", false, "hash"),
				new X509V3ExtensionValue("authorityKeyIdentifier", false, "keyid:always,issuer:always"),
				new X509V3ExtensionValue("basicConstraints", true, "critical,CA:true"),
				new X509V3ExtensionValue("keyUsage", false, "cRLSign,keyCertSign"),
			};

			using (var root = X509CertificateAuthority.SelfSigned(
				                  new SimpleSerialNumber(),
				                  key,
				                  MessageDigest.SHA1,
				                  "Root1",
				                  DateTime.Now,
				                  TimeSpan.FromDays(365),
				                  extList))
			{
				Console.WriteLine(root.Certificate);
				// Iterate the extensions
				Console.WriteLine("X509v3 Extensions:");
				foreach (var ext in root.Certificate.Extensions)
				{
					Console.WriteLine("Name:{0}, IsCritical:{1}, Value:{2}", ext.Name, ext.IsCritical, ext);
				}
			}
		}

		private static int OnGenerator(int p, int n, object arg)
		{
			TextWriter cout = Console.Error;

			switch (p)
			{
			case 0:
				cout.Write('.');
				break;
			case 1:
				cout.Write('+');
				break;
			case 2:
				cout.Write('*');
				break;
			case 3:
				cout.WriteLine();
				break;
			}

			return 1;
		}
	}
}
