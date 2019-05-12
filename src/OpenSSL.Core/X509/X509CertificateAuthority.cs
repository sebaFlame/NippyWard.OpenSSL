// Copyright (c) 2006-2008 Frank Laub
// All rights reserved.

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
using System.Runtime.InteropServices;

using OpenSSL.Core.Interop.SafeHandles.Crypto;
using OpenSSL.Core.Interop.SafeHandles.X509;
using OpenSSL.Core.Interop.SafeHandles;
using OpenSSL.Core.Keys;
using OpenSSL.Core.ASN1;
using OpenSSL.Core.Interop;
using OpenSSL.Core.Error;

namespace OpenSSL.Core.X509
{
	/// <summary>
	/// High-level interface which does the job of a CA (Certificate Authority)
	/// Duties include processing incoming X509 requests and responding
	/// with signed X509 certificates, signed by this CA's private key.
	/// </summary>
	public class X509CertificateAuthority : OpenSslBase
    {
        private X509Certificate caCert;
        private PrivateKey caKey;
        private ISequenceNumber serial;

        /// <summary>
        /// Accessor to the CA's X509 Certificate
        /// </summary>
        public X509Certificate Certificate
        {
            get { return caCert; }
        }

        /// <summary>
        /// Accessor to the CA's key used for signing.
        /// </summary>
        public PrivateKey Key
        {
            get { return caKey; }
        }

        #region Initialization

        public static X509CertificateAuthority CreateX509CertificateAuthority(
            int keyBits, 
            string OU, 
            string CN, 
            DateTime notBefore, 
            DateTime notAfter,
            out X509Certificate caCert,
            DigestType signHash = null,
            ISequenceNumber serialGenerator = null)
        {
            using (RSAKey rsaKey = new RSAKey(keyBits))
            {
                rsaKey.GenerateKey();

                caCert = new X509Certificate(rsaKey, OU, CN, notBefore, notAfter);

                caCert.AddExtension(caCert, null, X509ExtensionType.BasicConstraints, "CA:TRUE");
                caCert.AddExtension(caCert, null, X509ExtensionType.SubjectKeyIdentifier, "hash");
                caCert.AddExtension(caCert, null, X509ExtensionType.AuthorityKeyIdentifier, "keyid:always");

                caCert.SelfSign(rsaKey, signHash ?? DigestType.SHA256);
            }

            return new X509CertificateAuthority(caCert, caCert.PublicKey, serialGenerator ?? new SimpleSerialNumber());
        }

        /// <summary>
        /// Constructs a X509CertifcateAuthority with the specified parameters.
        /// </summary>
        /// <param name="caCert"></param>
        /// <param name="caKey"></param>
        /// <param name="serial"></param>
        public X509CertificateAuthority(X509Certificate caCert, PrivateKey caKey, ISequenceNumber serial)
            : base()
		{
			if (!caCert.VerifyPrivateKey(caKey))
				throw new Exception("The specified CA Private Key does match the specified CA Certificate");

            this.caCert = caCert;
			this.caKey = caKey;
			this.serial = serial;
		}

		#endregion

		#region Methods

		public X509Certificate ProcessRequest(
            X509CertificateRequest request,
			DateTime startTime,
			DateTime endTime,
			DigestType digestType)
		{
            //convert and sign
            //do not use X509_REQ_to_X509 as it uses MD5 to sign
            SafeX509CertificateHandle certHandle = this.CryptoWrapper.X509_new();

            //set the correct subjects
            SafeX509NameHandle x509Name = this.CryptoWrapper.X509_REQ_get_subject_name(request.X509RequestWrapper.Handle);
            this.CryptoWrapper.X509_set_subject_name(certHandle, x509Name);

            //set the correct issues
            this.CryptoWrapper.X509_set_issuer_name(certHandle, this.caCert.X509Name.X509NameWrapper.Handle);

            //set the public key
            this.CryptoWrapper.X509_set_pubkey(certHandle, request.PublicKey.KeyWrapper.Handle);

            //create managed wrapper
            X509Certificate cert = new X509Certificate(certHandle);

            //set correct properties
            cert.NotBefore = startTime;
            cert.NotAfter = endTime;
            cert.Version = request.Version;

            //assign correct serial number
            cert.SerialNumber = this.serial.Next();

            cert.AddExtension(this.caCert, request, X509ExtensionType.SubjectKeyIdentifier, "hash");
            cert.AddExtension(this.caCert, request, X509ExtensionType.AuthorityKeyIdentifier, "keyid:always");

            //sign the request with the CA key
            cert.Sign(this.caKey, digestType);

            return cert;
		}

		#endregion
	}
}
