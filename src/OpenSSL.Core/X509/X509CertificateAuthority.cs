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
	public class X509CertificateAuthority : OpenSslBase, IDisposable
    {
        private const string _DefaultCAKeyUsage = "critical,cRLSign,keyCertSign";

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
            ISequenceNumber serialGenerator = null,
            string keyUsage = _DefaultCAKeyUsage)
        {
            RSAKey rsaKey = new RSAKey(keyBits);
            rsaKey.GenerateKey();

            caCert = new X509Certificate(rsaKey, OU, CN, notBefore, notAfter);

            //set issuer as subject (self signed)
            SafeX509NameHandle x509Name = CryptoWrapper.X509_get_subject_name(caCert.X509Wrapper.Handle);
            CryptoWrapper.X509_set_issuer_name(caCert.X509Wrapper.Handle, x509Name);

            //subject hash (issuer also subject)
            caCert.AddExtension(caCert, null, X509ExtensionType.SubjectKeyIdentifier, "hash");

            //is a CA
            caCert.AddExtension(caCert, null, X509ExtensionType.BasicConstraints, "critical,CA:true");

            //can sign CLR & certificates
            //all usages should be in a single extension, hence the single argument
            caCert.AddExtension(caCert, null, X509ExtensionType.KeyUsage, keyUsage);

            //sign certificate
            caCert.Sign(rsaKey, signHash ?? DigestType.SHA256);

            return new X509CertificateAuthority(caCert, rsaKey, serialGenerator ?? new SimpleSerialNumber());
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
            {
                throw new Exception("The specified CA Private Key does not match the specified CA Certificate");
            }

            this.caCert = caCert;
			this.caKey = caKey;
			this.serial = serial;
		}

		#endregion

		#region Methods

		public X509Certificate ProcessRequest
        (
            X509CertificateRequest request,
			DateTime startTime,
			DateTime endTime
        )
		{
            SafeX509NameHandle x509Name;
            SafeKeyHandle requestKey;

            //get the key from the request
            requestKey = CryptoWrapper.X509_REQ_get0_pubkey(request.X509RequestWrapper.Handle);

            //and verify with the request
            CryptoWrapper.X509_REQ_verify(request.X509RequestWrapper.Handle, requestKey);

            //convert and sign
            //do not use X509_REQ_to_X509 as it uses MD5 to sign
            SafeX509CertificateHandle certHandle = CryptoWrapper.X509_new();

            //create managed wrapper
            X509Certificate cert = new X509Certificate(certHandle);

            //assign correct serial number
            cert.SerialNumber = this.serial.Next();

            //set the correct issuer
            x509Name = CryptoWrapper.X509_get_subject_name(this.caCert.X509Wrapper.Handle);
            CryptoWrapper.X509_set_issuer_name(certHandle, x509Name);

            //set the correct subject
            x509Name = CryptoWrapper.X509_REQ_get_subject_name(request.X509RequestWrapper.Handle);
            CryptoWrapper.X509_set_subject_name(certHandle, x509Name);

            //set correct properties
            cert.NotBefore = startTime;
            cert.NotAfter = endTime;
            cert.Version = request.Version;

            //set the public key
            requestKey = CryptoWrapper.X509_REQ_get0_pubkey(request.X509RequestWrapper.Handle);
            CryptoWrapper.X509_set_pubkey(certHandle, requestKey);

            //subject hash
            cert.AddExtension(this.caCert, request, X509ExtensionType.SubjectKeyIdentifier, "hash");

            //issuer hash
            cert.AddExtension(this.caCert, request, X509ExtensionType.AuthorityKeyIdentifier, "keyid:always");

            return cert;
		}

        public void Sign(X509Certificate certificate, DigestType digestType = null)
        {
            //get the key from the certificate
            SafeKeyHandle certKey = CryptoWrapper.X509_get0_pubkey(certificate.X509Wrapper.Handle);
            SafeKeyHandle caKey = this.caKey.KeyWrapper.Handle;

            if (CryptoWrapper.EVP_PKEY_missing_parameters(certKey) == 1
                && CryptoWrapper.EVP_PKEY_missing_parameters(caKey) == 0)
            {
                CryptoWrapper.EVP_PKEY_copy_parameters(certKey, caKey);
            }

            //sign the request with the CA key
            //certificate.Sign(this.caKey, digestType ?? DigestType.SHA256);
            this.Sign(certificate.X509Wrapper.Handle, digestType ?? DigestType.SHA256);
        }

        private void Sign(SafeX509CertificateHandle certHandle, DigestType digestType)
        {
            using(SafeMessageDigestContextHandle ctx = CryptoWrapper.EVP_MD_CTX_new())
            {
                using (SafeMessageDigestHandle md = CryptoWrapper.EVP_get_digestbyname(digestType.ShortNamePtr))
                {
                    CryptoWrapper.EVP_DigestSignInit
                    (
                        ctx,
                        out SafeKeyContextHandle pctx,
                        md,
                        SafeEngineHandle.Zero,
                        this.caKey.KeyWrapper.Handle
                    );

                    CryptoWrapper.X509_sign_ctx(certHandle, ctx);
                }
            }
        }

		#endregion

        public void Dispose()
        {
            this.caKey?.Dispose();
            this.caCert?.Dispose();
        }
	}
}
