using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

using OpenSSL.Core.Interop.Attributes;
using OpenSSL.Core.Interop.SafeHandles;

namespace OpenSSL.Core.Interop.Wrappers
{
    internal delegate void OPENSSL_sk_freefunc(IntPtr ptr);

    internal interface IStackWrapper
    {
        #region STACKOF
        [return: TakeOwnership]
        SafeStackHandle<TStackable> OPENSSL_sk_new_null<TStackable>()
            where TStackable : SafeBaseHandle, IStackable;
        [return: DontVerifyType]
        int OPENSSL_sk_num<TStackable>(SafeStackHandle<TStackable> stack)
            where TStackable : SafeBaseHandle, IStackable;
        [return: DontVerifyType]
        int OPENSSL_sk_find<TStackable>(SafeStackHandle<TStackable> stack, TStackable data)
            where TStackable : SafeBaseHandle, IStackable;
        int OPENSSL_sk_insert<TStackable>(SafeStackHandle<TStackable> stack, TStackable data, int where)
            where TStackable : SafeBaseHandle, IStackable;
        TStackable OPENSSL_sk_shift<TStackable>(SafeStackHandle<TStackable> stack)
            where TStackable : SafeBaseHandle, IStackable;
        int OPENSSL_sk_unshift<TStackable>(SafeStackHandle<TStackable> stack, TStackable data)
            where TStackable : SafeBaseHandle, IStackable;
        int OPENSSL_sk_push<TStackable>(SafeStackHandle<TStackable> stack, TStackable data)
            where TStackable : SafeBaseHandle, IStackable;
        TStackable OPENSSL_sk_pop<TStackable>(SafeStackHandle<TStackable> stack)
            where TStackable : SafeBaseHandle, IStackable;
        [return: DontVerifyType]
        TStackable OPENSSL_sk_delete<TStackable>(SafeStackHandle<TStackable> stack, int loc)
            where TStackable : SafeBaseHandle, IStackable;
        [return: DontVerifyType]
        TStackable OPENSSL_sk_delete_ptr<TStackable>(SafeStackHandle<TStackable> stack, TStackable p)
            where TStackable : SafeBaseHandle, IStackable;
        TStackable OPENSSL_sk_value<TStackable>(SafeStackHandle<TStackable> stack, int index)
            where TStackable : SafeBaseHandle, IStackable;
        /* returns inserted date: undefined behaviour because it might return a reference it owns, without
         * reference count being increased
        TStackable OPENSSL_sk_set<TStackable>(SafeStackHandle<TStackable> stack, int index, TStackable data)
            where TStackable : SafeBaseHandle, IStackable; */
        IntPtr OPENSSL_sk_dup<TStackable>(SafeStackHandle<TStackable> stack)
            where TStackable : SafeBaseHandle, IStackable;
        void OPENSSL_sk_zero<TStackable>(SafeStackHandle<TStackable> stack)
            where TStackable : SafeBaseHandle, IStackable;
        void OPENSSL_sk_free(IntPtr stack);
        //void OPENSSL_sk_pop_free(OPENSSL_STACK* st, OPENSSL_sk_freefunc func)
        void OPENSSL_sk_pop_free<TStackable>(SafeStackHandle<TStackable> stack, OPENSSL_sk_freefunc func)
            where TStackable : SafeBaseHandle, IStackable;
        #endregion
    }
}
