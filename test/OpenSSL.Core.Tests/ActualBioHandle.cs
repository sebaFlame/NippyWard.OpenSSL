using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

using OpenSSL.Core.Interop.SafeHandles;
using OpenSSL.Core.Interop.SafeHandles.Crypto;

namespace OpenSSL.Core.Tests
{
    internal class SafeStackHandle_ref<T> : SafeStackHandle<T>
        where T : SafeBaseHandle, IStackable
    {
        internal SafeStackHandle_ref()
            :base(false, false) { }

        internal SafeStackHandle_ref(IntPtr ptr, bool ownsHandle, bool isNew)
            : base(ptr, ownsHandle, isNew)
        {  }
    }

    internal class TestValue : SafeBaseHandle, IStackable
    {
        public TestValue()
            : base(false, false) { }

        protected override bool ReleaseHandle()
        {
            throw new NotImplementedException();
        }

        internal override void PostConstruction()
        {
            throw new NotImplementedException();
        }
    }

    internal class BioImplement : SafeBioHandle
    {
        private BioImplement()
            : base (true, true) { }

        internal BioImplement(IntPtr ptr, bool takeOwnership)
            : base(ptr, takeOwnership) { }
    }

    internal class RSAImplement : SafeRSAHandle
    {
        private RSAImplement()
            : base(true, true) { }
    }

    internal class TestOwnStackable
    {
        [DllImport("bleh.dll")]
        public static extern IntPtr sk_new_null_native();

        SafeStackHandle<TStackable> sk_new_null<TStackable>()
            where TStackable : SafeBaseHandle, IStackable
        {
            IntPtr ptr = sk_new_null_native();
            return new SafeStackHandle_ref<TStackable>(ptr, true, true);
        }

        [DllImport("bleh.dll")]
        public static extern IntPtr sk_value_native(IntPtr stack, int index);

        TStackable sk_value<TStackable>(SafeStackHandle<TStackable> stack, int index)
            where TStackable : SafeBaseHandle, IStackable
        {
            IntPtr stackPtr = stack.DangerousGetHandle();
            IntPtr ptr = sk_value_native(stackPtr, index);
            return SafeStackHandle<TStackable>.CreateSafeBaseHandle(ptr, true);
        }

        [DllImport("bleh.dll")]
        public static extern BioImplement BIO_new_native(IntPtr type);

        [DllImport("bleh.dll")]
        public static extern int sk_do_a_thing_native(out BioImplement bio, out IntPtr val);


        public int do_a_thing(out SafeBioHandle bio, out SafeStackHandle<TestValue> val)
        {
            BioImplement bioImplement;
            IntPtr ptr;

            int ret = sk_do_a_thing_native(out bioImplement, out ptr);
            bio = bioImplement;
            val = new SafeStackHandle_ref<TestValue>(ptr, true, true);

            return ret;
        }

        public SafeBioHandle BIO_new(IntPtr type)
        {
            return BIO_new_native(type);
        }

        [DllImport("bleh.dll")]
        public static extern RSAImplement PEM_read_bio_RSAPrivateKey_native(SafeBioHandle bp, ref SafeRSAHandle x);

        public SafeRSAHandle PEM_read_bio_RSAPrivateKey(SafeBioHandle bp, ref SafeRSAHandle x)
        {
            SafeRSAHandle retVal = PEM_read_bio_RSAPrivateKey_native(bp, ref x);
            return retVal;
        }

        [DllImport("bleh.dll")]
        public static extern RSAImplement d2i_PKCS12_bio_native(SafeBioHandle bp, out RSAImplement ptr);

        public SafeRSAHandle d2i_PKCS12_bio(SafeBioHandle bp, out SafeRSAHandle ptr)
        {
            RSAImplement outVal;
            SafeRSAHandle ret = d2i_PKCS12_bio_native(bp, out outVal);
            ptr = outVal;
            return ret;
        }

        //[DllImport("bleh.dll")]
        //public static extern SafeBioHandle do_a_thing_null_native(SafeBioHandle bp);

        //public SafeBioHandle do_a_thing_null(SafeBioHandle bp)
        //{
        //    if (SafeBaseHandle.GetNULL<SafeBioHandle>() is null)
        //        SafeBaseHandle.SetNULL<SafeBioHandle>(new BioImplement(IntPtr.Zero, false));

        //    return do_a_thing_null_native(bp ?? SafeBaseHandle.GetNULL<SafeBioHandle>());
        //}

        //[DllImport("bleh.dll")]
        //public static extern IntPtr do_a_thing_null_generic_native(IntPtr bp);

        //public SafeStackHandle<TStackable> do_a_thing_null_generic<TStackable>(SafeStackHandle<TStackable> bp)
        //    where TStackable : SafeBaseHandle, IStackable
        //{
        //    if (SafeBaseHandle.GetNULL<SafeStackHandle<TStackable>>() is null)
        //        SafeBaseHandle.SetNULL<SafeStackHandle<TStackable>>(new SafeStackHandle_ref<TStackable>(IntPtr.Zero, false, false));

        //    IntPtr ptr = do_a_thing_null_generic_native(bp?.DangerousGetHandle() ?? SafeBaseHandle.GetNULL<SafeStackHandle<TStackable>>().DangerousGetHandle());
        //    return new SafeStackHandle_ref<TStackable>(ptr, true, true);
        //}

        List<SafeStackHandle<TestValue>> bleh;

        public TestOwnStackable()
        {
            bleh = new List<SafeStackHandle<TestValue>>();
            bleh.Add(new SafeStackHandle_ref<TestValue>());
        }
    }
}
