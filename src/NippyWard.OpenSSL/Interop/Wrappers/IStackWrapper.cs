using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

using NippyWard.OpenSSL.Interop.Attributes;
using NippyWard.OpenSSL.Interop.SafeHandles;

namespace NippyWard.OpenSSL.Interop.Wrappers
{
    //void (*OPENSSL_sk_freefunc)(void *);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate void OPENSSL_sk_freefunc(IntPtr ptr);

    internal interface IStackWrapper
    {
        #region STACKOF
        //OPENSSL_STACK *OPENSSL_sk_new_null(void);
        [return: TakeOwnership]
        SafeStackHandle<TStackable> OPENSSL_sk_new_null<TStackable>()
            where TStackable : SafeBaseHandle, IStackable;
        //int OPENSSL_sk_num(const OPENSSL_STACK *);
        [return: DontVerifyType]
        int OPENSSL_sk_num<TStackable>(SafeStackHandle<TStackable> stack)
            where TStackable : SafeBaseHandle, IStackable;
        //int OPENSSL_sk_find(OPENSSL_STACK *st, const void *data);
        [return: DontVerifyType]
        int OPENSSL_sk_find<TStackable>(SafeStackHandle<TStackable> stack, TStackable data)
            where TStackable : SafeBaseHandle, IStackable;
        //int OPENSSL_sk_insert(OPENSSL_STACK *sk, const void *data, int where);
        int OPENSSL_sk_insert<TStackable>(SafeStackHandle<TStackable> stack, TStackable data, int where)
            where TStackable : SafeBaseHandle, IStackable;
        //void *OPENSSL_sk_shift(OPENSSL_STACK *st);
        TStackable OPENSSL_sk_shift<TStackable>(SafeStackHandle<TStackable> stack)
            where TStackable : SafeBaseHandle, IStackable;
        //int OPENSSL_sk_unshift(OPENSSL_STACK *st, const void *data);
        int OPENSSL_sk_unshift<TStackable>(SafeStackHandle<TStackable> stack, TStackable data)
            where TStackable : SafeBaseHandle, IStackable;
        //int OPENSSL_sk_push(OPENSSL_STACK *st, const void *data);
        int OPENSSL_sk_push<TStackable>(SafeStackHandle<TStackable> stack, TStackable data)
            where TStackable : SafeBaseHandle, IStackable;
        //void *OPENSSL_sk_pop(OPENSSL_STACK *st);
        TStackable OPENSSL_sk_pop<TStackable>(SafeStackHandle<TStackable> stack)
            where TStackable : SafeBaseHandle, IStackable;
        //void *OPENSSL_sk_delete(OPENSSL_STACK *st, int loc);
        [return: DontVerifyType]
        TStackable OPENSSL_sk_delete<TStackable>(SafeStackHandle<TStackable> stack, int loc)
            where TStackable : SafeBaseHandle, IStackable;
        //void *OPENSSL_sk_delete_ptr(OPENSSL_STACK *st, const void *p);
        [return: DontVerifyType]
        TStackable OPENSSL_sk_delete_ptr<TStackable>(SafeStackHandle<TStackable> stack, TStackable p)
            where TStackable : SafeBaseHandle, IStackable;
        //void *OPENSSL_sk_value(const OPENSSL_STACK *, int);
        TStackable OPENSSL_sk_value<TStackable>(SafeStackHandle<TStackable> stack, int index)
            where TStackable : SafeBaseHandle, IStackable;
        /* returns inserted date: undefined behaviour because it might return a reference it owns, without
         * reference count being increased
        TStackable OPENSSL_sk_set<TStackable>(SafeStackHandle<TStackable> stack, int index, TStackable data)
            where TStackable : SafeBaseHandle, IStackable; */
        //OPENSSL_STACK *OPENSSL_sk_dup(const OPENSSL_STACK *st);
        IntPtr OPENSSL_sk_dup<TStackable>(SafeStackHandle<TStackable> stack)
            where TStackable : SafeBaseHandle, IStackable;
        //void OPENSSL_sk_zero(OPENSSL_STACK *st);
        void OPENSSL_sk_zero<TStackable>(SafeStackHandle<TStackable> stack)
            where TStackable : SafeBaseHandle, IStackable;
        //void OPENSSL_sk_free(OPENSSL_STACK *);
        void OPENSSL_sk_free(IntPtr stack);
        //void OPENSSL_sk_pop_free(OPENSSL_STACK* st, OPENSSL_sk_freefunc func)
        void OPENSSL_sk_pop_free<TStackable>(SafeStackHandle<TStackable> stack, OPENSSL_sk_freefunc func)
            where TStackable : SafeBaseHandle, IStackable;
        #endregion
    }
}
