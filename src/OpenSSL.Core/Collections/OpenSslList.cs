using System;
using System.Reflection;
using System.Linq.Expressions;

using OpenSSL.Core.Interop.SafeHandles;
using System.Collections;
using System.Collections.Generic;

namespace OpenSSL.Core.Collections
{
    public class OpenSslList<T> : OpenSslEnumerable<T>, IList<T>
        where T : OpenSslWrapperBase
    {
        internal static Func<IOpenSslIList<T>> CreateInternalList;
        internal static Func<object, IOpenSslIList<T>> CreateSafeStackInternalList;

        public int Count => this.InternalList.Count;
        public bool IsReadOnly => this.InternalList.IsReadOnly;
        public T this[int index]
        {
            get => this.InternalList[index];
            set => this.InternalList[index] = value;
        }

        internal override IOpenSslIEnumerable<T> InternalEnumerable => this.InternalList;

        private IOpenSslIList<T> InternalList;

        static OpenSslList()
        {
            Type type = typeof(T);

            WrapperAttribute attr = type.GetCustomAttribute<WrapperAttribute>();
            if (attr is null)
                throw new NullReferenceException("Wrapper type not found");

            Type wrapperType = attr.WrapperType;
            if (!wrapperType.BaseType.IsGenericType)
                throw new InvalidOperationException("Invalid base type");
            Type safeHandleType = wrapperType.BaseType.GetGenericArguments()[0];

            //new list
            Type stackType = typeof(OpenSslListWrapper<,,>).GetGenericTypeDefinition();
            Type constructedWrapperType = stackType.MakeGenericType(type, wrapperType, safeHandleType);

            ConstructorInfo newCtor = constructedWrapperType.GetConstructor(BindingFlags.NonPublic | BindingFlags.Instance, null, Type.EmptyTypes, null);
            Expression newConstruction = Expression.New(newCtor);
            CreateInternalList = Expression.Lambda<Func<IOpenSslIList<T>>>(newConstruction).Compile();

            //from existing list
            Type constructedStackType = typeof(SafeStackHandle<>).MakeGenericType(safeHandleType);
            ConstructorInfo existingCtor = constructedWrapperType.GetConstructor(BindingFlags.NonPublic | BindingFlags.Instance, null, new Type[] { constructedStackType }, null);
            ParameterExpression parameterExpression = Expression.Parameter(typeof(object));
            Expression castExpression = Expression.TypeAs(parameterExpression, constructedStackType);
            Expression existingConstruction = Expression.New(existingCtor, castExpression);
            CreateSafeStackInternalList = Expression.Lambda<Func<object, IOpenSslIList<T>>>(existingConstruction, parameterExpression).Compile();
        }

        public OpenSslList()
        {
            this.InternalList = CreateInternalList();
        }

        private OpenSslList(object stackHandle)
        {
            this.InternalList = CreateSafeStackInternalList(stackHandle);
        }

        internal static OpenSslList<T> CreateFromSafeHandle<THandle>(SafeStackHandle<THandle> stackHandle)
            where THandle : SafeBaseHandle, IStackable
        {
            return new OpenSslList<T>(stackHandle);
        }

        public int IndexOf(T item)
        {
            return this.InternalList.IndexOf(item);
        }

        public void Insert(int index, T item)
        {
            this.InternalList.Insert(index, item);
        }

        public void RemoveAt(int index)
        {
            this.InternalList.RemoveAt(index);
        }

        public void Add(T item)
        {
            this.InternalList.Add(item);
        }

        public void Clear()
        {
            this.InternalList.Clear();
        }

        public bool Contains(T item)
        {
            return this.InternalList.Contains(item);
        }

        public void CopyTo(T[] array, int arrayIndex)
        {
            throw new NotImplementedException();
        }

        public bool Remove(T item)
        {
            return this.InternalList.Remove(item);
        }
    }
}
