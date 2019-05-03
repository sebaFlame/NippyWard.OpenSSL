using System;
using System.Reflection;
using System.Linq.Expressions;
using System.Runtime.InteropServices;

using OpenSSL.Core.Interop.SafeHandles;
using System.Collections;
using System.Collections.Generic;

namespace OpenSSL.Core.Collections
{
    public class OpenSslReadOnlyCollection<T> : OpenSslEnumerable<T>, IReadOnlyCollection<T>
        where T : OpenSslWrapperBase
    {
        internal static Func<IOpenSslIReadOnlyCollection<T>> CreateInternalList;
        internal static Func<object, IOpenSslIReadOnlyCollection<T>> CreateSafeStackInternalList;

        public int Count => this.InternalList.Count;

        private IOpenSslIReadOnlyCollection<T> InternalList;

        internal override IOpenSslIEnumerable<T> InternalEnumerable => this.InternalList;

        static OpenSslReadOnlyCollection()
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
            Type stackType = typeof(OpenSslReadOnlyWrapper<,,>).GetGenericTypeDefinition();
            Type constructedWrapperType = stackType.MakeGenericType(type, wrapperType, safeHandleType);

            ConstructorInfo newCtor = constructedWrapperType.GetConstructor(BindingFlags.NonPublic | BindingFlags.Instance, null, Type.EmptyTypes, null);
            Expression newConstruction = Expression.New(newCtor);
            CreateInternalList = Expression.Lambda<Func<IOpenSslIReadOnlyCollection<T>>>(newConstruction).Compile();

            //from existing list
            Type constructedStackType = typeof(SafeStackHandle<>).MakeGenericType(safeHandleType);
            ConstructorInfo existingCtor = constructedWrapperType.GetConstructor(BindingFlags.NonPublic | BindingFlags.Instance, null, new Type[] { constructedStackType }, null);
            ParameterExpression parameterExpression = Expression.Parameter(typeof(object));
            Expression castExpression = Expression.TypeAs(parameterExpression, constructedStackType);
            Expression existingConstruction = Expression.New(existingCtor, castExpression);
            CreateSafeStackInternalList = Expression.Lambda<Func<object, IOpenSslIReadOnlyCollection<T>>>(existingConstruction, parameterExpression).Compile();
        }

        public OpenSslReadOnlyCollection()
        {
            this.InternalList = CreateInternalList();
        }

        private OpenSslReadOnlyCollection(object stackHandle)
        {
            this.InternalList = CreateSafeStackInternalList(stackHandle);
        }

        internal static OpenSslReadOnlyCollection<T> CreateFromSafeHandle<THandle>(SafeStackHandle<THandle> stackHandle)
            where THandle : SafeBaseHandle, IStackable
        {
            return new OpenSslReadOnlyCollection<T>(stackHandle);
        }
    }
}
