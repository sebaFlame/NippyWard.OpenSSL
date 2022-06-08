using System;
using System.Reflection;
using System.Linq.Expressions;
using System.Runtime.InteropServices;

using OpenSSL.Core.Interop.SafeHandles;
using System.Collections;
using System.Collections.Generic;

namespace OpenSSL.Core.Collections
{
    internal class OpenSslList<TOuter, TInner>
        : OpenSslWrapperBase,
            IList<TOuter>,
            IOpenSslReadOnlyCollection<TOuter>,
            ISafeHandleWrapper<SafeStackHandle<TInner>>
        where TInner : SafeBaseHandle, IStackable
        where TOuter : OpenSslWrapperBase, ISafeHandleWrapper<TInner>
    {
        public int Count => this._Handle.Count;
        public bool IsReadOnly => this._Handle.IsReadOnly;

        SafeStackHandle<TInner> ISafeHandleWrapper<SafeStackHandle<TInner>>.Handle
            => this._Handle;
        public override SafeHandle Handle
            => this._Handle;

        static readonly Func<TInner, TOuter> _CreateWrapperInstance;

        static OpenSslList()
        {
            Type outerType = typeof(TOuter);
            Type innerType = typeof(TInner);

            ConstructorInfo? newCtor = outerType.GetConstructor
            (
                BindingFlags.NonPublic | BindingFlags.Instance,
                null,
                new Type[]
                {
                    innerType
                },
                null
            );
            
            if(newCtor is null)
            {
                throw new NullReferenceException($"{outerType} does not have a constructor with a single {innerType}");
            }
            
            ParameterExpression parameterExpression = Expression.Parameter(typeof(TInner));
            Expression newConstruction = Expression.New(newCtor, parameterExpression);
            _CreateWrapperInstance = Expression.Lambda<Func<TInner, TOuter>>(newConstruction, parameterExpression).Compile();
        }

        public TOuter this[int index]
        {
            get => CreateStackableWrapperItem(this._Handle[index]);
            set => this._Handle[index] = (value as ISafeHandleWrapper<TInner>).Handle!;
        }

        internal readonly SafeStackHandle<TInner> _Handle;

        public OpenSslList(SafeStackHandle<TInner> stackHandle)
        {
            this._Handle = stackHandle;
        }

        public int IndexOf(TOuter item)
        {
            return this._Handle.IndexOf((item as ISafeHandleWrapper<TInner>).Handle!);
        }

        public void Insert(int index, TOuter item)
        {
            this._Handle.Insert(index, (item as ISafeHandleWrapper<TInner>).Handle!);
        }

        public void RemoveAt(int index)
        {
            this._Handle.RemoveAt(index);
        }

        public void Add(TOuter item)
        {
            this._Handle.Add((item as ISafeHandleWrapper<TInner>).Handle!);
        }

        public void Clear()
        {
            this._Handle.Clear();
        }

        public bool Contains(TOuter item)
        {
            return this._Handle.Contains((item as ISafeHandleWrapper<TInner>).Handle!);
        }

        public void CopyTo(TOuter[] array, int arrayIndex)
        {
            throw new NotImplementedException();
        }

        public bool Remove(TOuter item)
        {
            return this._Handle.Remove((item as ISafeHandleWrapper<TInner>).Handle!);
        }

        public IEnumerator<TOuter> GetEnumerator()
        {
            return new Enumerator(this);
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return new Enumerator(this);
        }

        internal static TOuter CreateStackableWrapperItem(TInner item)
        {
            TOuter t = _CreateWrapperInstance(item);
            return t;
        }

        #region Enumerator
        private class Enumerator : IEnumerator<TOuter>
        {
            private readonly IEnumerator<TInner> _enumerator;

            public Enumerator(OpenSslList<TOuter, TInner> list)
            {
                this._enumerator = list._Handle.GetEnumerator();
            }

            public TOuter Current
                => CreateStackableWrapperItem(this._enumerator.Current);
            object IEnumerator.Current => this.Current;

            public bool MoveNext()
                => this._enumerator.MoveNext();

            public void Reset()
                => this._enumerator.Reset();

            public void Dispose()
                => this._enumerator.Dispose();
        }
        #endregion

        protected override void Dispose(bool disposing)
        {
            //NOP
        }
    }
}
