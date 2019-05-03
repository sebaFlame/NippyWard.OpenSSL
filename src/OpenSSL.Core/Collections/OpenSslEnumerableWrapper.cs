using System;
using System.Collections.Generic;
using System.Reflection;
using System.Linq.Expressions;

using OpenSSL.Core.Interop;
using OpenSSL.Core.Interop.SafeHandles;
using OpenSSL.Core.Interop.Wrappers;
using System.Collections;

namespace OpenSSL.Core.Collections
{
    internal abstract class OpenSslEnumerableWrapper<TOuter, TWrapper, THandle> : SafeHandleWrapper<SafeStackHandle<THandle>>, IOpenSslIEnumerable<TOuter>
        where THandle : SafeBaseHandle, IStackable
        where TWrapper : SafeHandleWrapper<THandle>
        where TOuter : OpenSslWrapperBase
    {
        internal static Func<TOuter, THandle> GetSafeHandle;
        internal static Func<THandle, TOuter> ConstructObject;

        static OpenSslEnumerableWrapper()
        {
            Type wrapperType = typeof(TWrapper);
            Type managedType = typeof(TOuter);
            Type handleType = typeof(THandle);

            MethodInfo getHandle = wrapperType.GetProperty("Handle", BindingFlags.Instance | BindingFlags.NonPublic).GetMethod;
            MethodInfo getWrapper = managedType.GetProperty("HandleWrapper", BindingFlags.Instance | BindingFlags.NonPublic).GetMethod;

            ParameterExpression handleParameter = Expression.Parameter(managedType);
            Expression callWrapper = Expression.Call(handleParameter, getWrapper);
            Expression castExpression = Expression.TypeAs(callWrapper, wrapperType);
            Expression callHandle = Expression.Call(castExpression, getHandle);

            GetSafeHandle = Expression.Lambda<Func<TOuter, THandle>>(callHandle, handleParameter).Compile();

            ConstructorInfo wrapperCtor = wrapperType.GetConstructor(BindingFlags.NonPublic | BindingFlags.Instance, null, new Type[] { handleType }, null);
            ParameterExpression objParameter = Expression.Parameter(handleType);
            Expression newWrapper = Expression.New(wrapperCtor, objParameter);

            ConstructorInfo objectCtor = managedType.GetConstructor(BindingFlags.NonPublic | BindingFlags.Instance, null, new Type[] { wrapperType }, null);
            Expression newObject = Expression.New(objectCtor, newWrapper);

            ConstructObject = Expression.Lambda<Func<THandle, TOuter>>(newObject, objParameter).Compile();
        }

        internal OpenSslEnumerableWrapper(SafeStackHandle<THandle> safeHandle)
            : base(safeHandle)
        { }

        internal OpenSslEnumerableWrapper()
            : base(Native.CryptoWrapper.OPENSSL_sk_new_null<THandle>())
        { }

        public IEnumerator<TOuter> GetEnumerator() => new OpenSslEnumerator(this.CryptoWrapper, this.Handle);
        IEnumerator IEnumerable.GetEnumerator() => new OpenSslEnumerator(this.CryptoWrapper, this.Handle);

        private struct OpenSslEnumerator : IEnumerator<TOuter>
        {
            private IEnumerator<THandle> stackEnumerator;
            private ILibCryptoWrapper CryptoWrapper;

            internal OpenSslEnumerator(
                ILibCryptoWrapper cryptoWrapper,
                SafeStackHandle<THandle> stackHandle)
            {
                this.CryptoWrapper = cryptoWrapper;
                this.stackEnumerator = stackHandle.GetEnumerator();
            }

            public TOuter Current => ConstructObject(stackEnumerator.Current);
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
