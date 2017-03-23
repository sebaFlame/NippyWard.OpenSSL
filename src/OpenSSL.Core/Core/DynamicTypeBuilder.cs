using System;
using System.Linq;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.InteropServices;

namespace OpenSSL.Core.Core
{
    public static class DynamicTypeBuilder
    {
        private static ModuleBuilder moduleBuilder;

        private static void createModuleBuilder()
        {
            AssemblyName asmName = new AssemblyName("OpenSSL.Core.Core.Dynamic");
            AssemblyBuilder asmBuilder = AssemblyBuilder.DefineDynamicAssembly(asmName, AssemblyBuilderAccess.Run);
            moduleBuilder = asmBuilder.DefineDynamicModule(asmName.Name);
        }

        internal static Type CreateOpenSSLWrapper<T>(string dllName)
        {
            if (!typeof(T).GetTypeInfo().IsInterface)
                throw new InvalidOperationException("Only interfaces allowed");

            if (moduleBuilder == null)
                createModuleBuilder();

            TypeBuilder typeBuilder = moduleBuilder.DefineType(typeof(T).Name.TrimStart('I'), TypeAttributes.Public);
            typeBuilder.AddInterfaceImplementation(typeof(T));

            MethodInfo[] interfaceMethod = typeof(T).GetTypeInfo().GetMethods();
            foreach (MethodInfo ifMethod in interfaceMethod)
                createInterfaceImplementation(dllName, typeBuilder, ifMethod);

            return typeBuilder.CreateTypeInfo().AsType();
        }

        private static void createInterfaceImplementation(string dllName, TypeBuilder typeBuilder, MethodInfo ifMethod)
        {
            CustomAttributeBuilder attrBuilder;
            Type attrType;
            Type[] ctorParams;
            ConstructorInfo ctor;
            MethodBuilder nativeMethod, interfaceMethod;
            ILGenerator interfaceMethodIL;
            Label lbl;
            LocalBuilder local;

            //get interface method info
            string methodName = ifMethod.Name;
            Type retType = ifMethod.ReturnType;
            ParameterInfo[] parameterInfo = ifMethod.GetParameters();
            Type[] parameterTypes = parameterInfo.Select(x => x.ParameterType).ToArray();

            //declare native method
            nativeMethod = typeBuilder.DefineMethod(string.Format("openssl_{0}", methodName),
                MethodAttributes.Private | MethodAttributes.PinvokeImpl | MethodAttributes.Static,
                retType, parameterTypes);

            //declare native method DllImportAttribute
            attrType = typeof(DllImportAttribute);
            ctorParams = new Type[] { typeof(string) };
            ctor = attrType.GetTypeInfo().GetConstructor(ctorParams);
            attrBuilder = new CustomAttributeBuilder(ctor, new object[] { dllName },
                new FieldInfo[] { attrType.GetTypeInfo().GetField("EntryPoint") },
                new object[] { methodName });
            nativeMethod.SetCustomAttribute(attrBuilder);

            //declare interface method
            interfaceMethod = typeBuilder.DefineMethod(methodName, MethodAttributes.Public | MethodAttributes.Virtual,
                retType, parameterTypes);
            interfaceMethodIL = interfaceMethod.GetILGenerator();

            //if native method has a return type, define a local and a label
            if (retType != typeof(void))
            {
                local = interfaceMethodIL.DeclareLocal(retType);
                lbl = interfaceMethodIL.DefineLabel();
            }

            interfaceMethodIL.Emit(OpCodes.Nop);

            //load arguments (as interface implementation you need to skip Ldarg_0)
            for (int i = 0; i < parameterTypes.Length; i++)
            {
                switch (i)
                {
                    case 0:
                        interfaceMethodIL.Emit(OpCodes.Ldarg_1);
                        break;
                    case 1:
                        interfaceMethodIL.Emit(OpCodes.Ldarg_2);
                        break;
                    case 2:
                        interfaceMethodIL.Emit(OpCodes.Ldarg_3);
                        break;
                    default:
                        interfaceMethodIL.Emit(OpCodes.Ldarg_S, (i + 1));
                        break;
                }
            }

            //execute native method
            interfaceMethodIL.Emit(OpCodes.Call, nativeMethod);

            //store and load return value
            if (retType != typeof(void))
            {
                interfaceMethodIL.Emit(OpCodes.Stloc_0);
                interfaceMethodIL.Emit(OpCodes.Br_S, lbl);
                interfaceMethodIL.MarkLabel(lbl);
                interfaceMethodIL.Emit(OpCodes.Ldloc_0);
            }
            else
                interfaceMethodIL.Emit(OpCodes.Nop);

            interfaceMethodIL.Emit(OpCodes.Ret);

            //define interface implementation as the interface override
            typeBuilder.DefineMethodOverride(interfaceMethod, ifMethod);
        }
    }
}
