using System;
using System.Collections;
using System.Collections.Generic;
using System.Text;

using OpenSSL.Core.Interop.Wrappers;
using OpenSSL.Core.Interop.SafeHandles.X509;

namespace OpenSSL.Core.X509
{
    internal class X509ExtensionEnumerator : IEnumerator<X509Extension>, ICollection<X509Extension>
    {
        private ILibCryptoWrapper cryptoWrapper;
        private int position;

        private Func<int, SafeX509ExtensionHandle> getExtension;
        private Func<int> getMaxCount;
        private Action<SafeX509ExtensionHandle> addExtension;

        internal X509ExtensionEnumerator(
            ILibCryptoWrapper cryptoWrapper,
            Func<int, SafeX509ExtensionHandle> getExtension, 
            Func<int> getMaxCount, 
            Action<SafeX509ExtensionHandle> addExtension)
        {
            this.cryptoWrapper = cryptoWrapper;
            this.getExtension = getExtension;
            this.getMaxCount = getMaxCount;
            this.addExtension = addExtension;
        }

        public X509Extension Current => new X509Extension(getExtension(this.position - 1));
        object IEnumerator.Current => this.Current;

        public int Count => this.getMaxCount();
        public bool IsReadOnly => false;

        public bool MoveNext()
        {
            if (++this.position < this.getMaxCount())
                return true;

            return false;
        }

        public void Reset()
        {
            this.position = 0;
        }

        IEnumerator IEnumerable.GetEnumerator() => this;
        public IEnumerator<X509Extension> GetEnumerator() => this;

        public void Dispose()
        {
            this.position = 0;
        }

        /// <summary>
        /// <paramref name="item"/> gets duplicated, remember to Dispose
        /// </summary>
        /// <param name="item">The extension to add</param>
        public void Add(X509Extension item)
        {
            this.addExtension(item.X509ExtensionWrapper.Handle);
        }

        //TODO: you can remove, but only by location
        //you can get the extension NID/OBJ
        //but multiple extensions of a certain NID are possible
        public bool Remove(X509Extension item)
        {
            throw new NotSupportedException();
        }

        public void Clear()
        {
            throw new NotSupportedException();
        }

        public bool Contains(X509Extension item)
        {
            throw new NotSupportedException();
        }

        public void CopyTo(X509Extension[] array, int arrayIndex)
        {
            throw new NotSupportedException();
        }
    }
}
