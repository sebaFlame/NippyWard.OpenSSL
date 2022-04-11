// Copyright (c) 2006-2007 Frank Laub
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
using System.Collections;
using System.Collections.Generic;
using System.Reflection;
using System.Linq.Expressions;
using OpenSSL.Core.Interop.Wrappers;

namespace OpenSSL.Core.Interop.SafeHandles
{
	/// <summary>
	/// The Stack class can only contain objects marked with this interface.
	/// </summary>
	public interface IStackable
	{ }

	internal interface IStack
	{ }

	/// <summary>
	/// Encapsulates the sk_* functions
	/// </summary>
	/// <typeparam name="T"></typeparam>
	internal abstract class SafeStackHandle<T> : BaseValue, IStack, IList<T>
		where T : SafeBaseHandle, IStackable
	{
        internal static SafeStackHandle<T> Zero
            => new SafeStackHandleWrapperSafeHandle<T>(IntPtr.Zero);

        internal override OPENSSL_sk_freefunc FreeFunc => this._freeFunc;

        public T this[int index]
        {
            get => StackWrapper.OPENSSL_sk_value(this, index);
            set => StackWrapper.OPENSSL_sk_insert(this, value, index);
        }
        public int Count => StackWrapper.OPENSSL_sk_num(this);
        public virtual bool IsReadOnly => false; //TODO: there are read-only collections

        private readonly OPENSSL_sk_freefunc _freeFunc;
        //ensures fucntion stays pinned
        private static OPENSSL_sk_freefunc _ItemFreeFunc;

        static SafeStackHandle()
        {
            Type itemType = typeof(T);

            //get the OPENSSL_sk_freefunc from the Zero instance
            //this instance property should reference a static method
            PropertyInfo zero = itemType.GetProperty(nameof(SafeBioHandle.Zero), BindingFlags.Static | BindingFlags.Public);
            PropertyInfo func = itemType.GetProperty(nameof(SafeBioHandle.FreeFunc), BindingFlags.Instance | BindingFlags.NonPublic);

            object zeroSafeHandle = zero.GetValue(null);
            _ItemFreeFunc = (OPENSSL_sk_freefunc)func.GetValue(zeroSafeHandle);
        }

        internal SafeStackHandle(bool takeOwnership)
            :base(takeOwnership)
        {
            this._freeFunc = new OPENSSL_sk_freefunc(this.Free);
        }

        internal SafeStackHandle(IntPtr ptr, bool takeOwnership)
            : base(ptr, takeOwnership)
        {
            this._freeFunc = new OPENSSL_sk_freefunc(this.Free);
        }

        public void Add(T item)
        {
            StackWrapper.OPENSSL_sk_push(this, item);
        }

        public void Clear()
        {
            StackWrapper.OPENSSL_sk_zero(this);
        }

        public bool Contains(T item)
        {
            return StackWrapper.OPENSSL_sk_find(this, item) >= 0;
        }

        public void CopyTo(T[] array, int arrayIndex)
        {
            throw new NotImplementedException();
        }

        public int IndexOf(T item)
        {
            return StackWrapper.OPENSSL_sk_find(this, item);
        }

        public void Insert(int index, T item)
        {
            StackWrapper.OPENSSL_sk_insert(this, item, index);
        }

        public bool Remove(T item)
        {
            T ret = StackWrapper.OPENSSL_sk_delete_ptr(this, item);
            return !EqualityComparer<T>.Default.Equals(ret, default(T));
        }

        public void RemoveAt(int index)
        {
            T ret = StackWrapper.OPENSSL_sk_delete(this, index);
            if (EqualityComparer<T>.Default.Equals(ret, default(T)))
                throw new ArgumentOutOfRangeException($"Element {index} not found");
        }

        internal void Free(IntPtr ptr)
        {
            if(this.TakeOwnership)
            {
                //do not throw an exception
                if (ptr != this.handle)
                {
                    return;
                }

                StackWrapper.OPENSSL_sk_pop_free(this, _ItemFreeFunc);
            }
            else
            {
                StackWrapper.OPENSSL_sk_free(ptr);
            }
        }

        public IEnumerator<T> GetEnumerator()
        {
            return new Enumerator(this);
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return new Enumerator(this);
        }

        #region Enumerator
        private struct Enumerator : IEnumerator<T>
        {
            private SafeStackHandle<T> stackHandle;
            private int position;

            public Enumerator(SafeStackHandle<T> stackHandle)
            {
                this.stackHandle = stackHandle;
                this.position = -1;
            }

            public T Current => StackWrapper.OPENSSL_sk_value(this.stackHandle, position);
            object IEnumerator.Current => this.Current;

            public bool MoveNext()
            {
                return ++position < this.stackHandle.Count;
            }

            public void Reset()
            {
                this.position = -1;
            }

            public void Dispose()
            {

            }
        }
        #endregion
    }
}
