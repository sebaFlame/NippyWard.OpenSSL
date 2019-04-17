using System;
using System.Collections;
using System.Collections.Generic;
using System.Text;

using OpenSSL.Core.Interop;
using OpenSSL.Core.Interop.Wrappers;
using OpenSSL.Core.Interop.SafeHandles;
using OpenSSL.Core.Interop.SafeHandles.X509;

namespace OpenSSL.Core.X509
{
    public class X509CertificateList : Base, IReadOnlyCollection<X509Certificate>
    {
        internal SafeStackHandle<SafeX509CertificateHandle> X509StackHandle { get; private set; }

        public int Count => this.X509StackHandle.Count;

        private X509CertificateList()
            : base()
        { }

        //IMPORTANT: the handle is now owned by this class
        internal X509CertificateList(SafeStackHandle<SafeX509CertificateHandle> stackHandle)
            : base()
        {
            this.X509StackHandle = stackHandle;
        }

        internal X509CertificateList(SafeX509StoreHandle storeHandle)
            : base()
        {
            SafeStackHandle<SafeX509ObjectHandle> stackHandle = this.CryptoWrapper.X509_STORE_get0_objects(storeHandle);
            this.X509StackHandle = this.CryptoWrapper.OPENSSL_sk_new_null<SafeX509CertificateHandle>();

            SafeX509CertificateHandle certificate;
            foreach (SafeX509ObjectHandle obj in stackHandle)
            {
                if (!((certificate = this.CryptoWrapper.X509_OBJECT_get0_X509(obj)) is null))
                    this.X509StackHandle.Add(certificate);
            }
        }

        ~X509CertificateList()
        {
            this.Dispose();
        }

        public override void Dispose()
        {
            if (!(this.X509StackHandle is null) && !this.X509StackHandle.IsInvalid)
                this.X509StackHandle.Dispose();
        }

        public IEnumerator<X509Certificate> GetEnumerator()
        {
            return new X509CertificateEnumerator(this.CryptoWrapper, this.X509StackHandle);
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return new X509CertificateEnumerator(this.CryptoWrapper, this.X509StackHandle);
        }

        private struct X509CertificateEnumerator : IEnumerator<X509Certificate>
        {
            private IEnumerator<SafeX509CertificateHandle> stackEnumerator;
            private ILibCryptoWrapper CryptoWrapper;

            internal X509CertificateEnumerator(
                ILibCryptoWrapper cryptoWrapper,
                SafeStackHandle<SafeX509CertificateHandle> stackHandle)
            {
                this.CryptoWrapper = cryptoWrapper;
                this.stackEnumerator = stackHandle.GetEnumerator();
            }

            public X509Certificate Current => new X509Certificate(stackEnumerator.Current);
            object IEnumerator.Current => this.Current;

            public void Dispose()
            {
                this.stackEnumerator.Dispose();
            }

            public bool MoveNext()
            {
                return this.stackEnumerator.MoveNext();
            }

            public void Reset()
            {
                this.stackEnumerator.Reset();
            }
        }
    }
}
