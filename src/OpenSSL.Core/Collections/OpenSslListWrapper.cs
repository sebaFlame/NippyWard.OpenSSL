using System;

using OpenSSL.Core.Interop.SafeHandles;

namespace OpenSSL.Core.Collections
{
    internal class OpenSslListWrapper<TOuter, TWrapper, THandle> : OpenSslEnumerableWrapper<TOuter, TWrapper, THandle>, IOpenSslIList<TOuter>
        where THandle : SafeBaseHandle, IStackable
        where TWrapper : SafeHandleWrapper<THandle>
        where TOuter : OpenSslWrapperBase
    {
        public int Count => this.Handle.Count;
        public bool IsReadOnly => this.Handle.IsReadOnly;

        public TOuter this[int index]
        {
            get => ConstructObject(this.Handle[index]);
            set => this.Handle[index] = GetSafeHandle(value);
        }

        internal OpenSslListWrapper(SafeStackHandle<THandle> safeHandle)
            : base(safeHandle)
        { }

        internal OpenSslListWrapper()
            : base()
        { }

        public int IndexOf(TOuter item)
        {
            return this.Handle.IndexOf(GetSafeHandle(item));
        }

        public void Insert(int index, TOuter item)
        {
            this.Handle.Insert(index, GetSafeHandle(item));
        }

        public void RemoveAt(int index)
        {
            this.Handle.RemoveAt(index);
        }

        public void Add(TOuter item)
        {
            this.Handle.Add(GetSafeHandle(item));
        }

        public void Clear()
        {
            this.Handle.Clear();
        }

        public bool Contains(TOuter item)
        {
            return this.Handle.Contains(GetSafeHandle(item));
        }

        public void CopyTo(TOuter[] array, int arrayIndex)
        {
            throw new NotImplementedException();
        }

        public bool Remove(TOuter item)
        {
            return this.Handle.Remove(GetSafeHandle(item));
        }
    }
}
