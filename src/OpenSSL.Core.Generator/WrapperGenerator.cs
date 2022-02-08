using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Diagnostics;

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Text;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace OpenSSL.Core.Generator
{
    /* TODO
     * Create Stack wrapper (using factory?)
     */
    [Generator]
    public partial class WrapperGenerator : ISourceGenerator
    {
        private const string _CryptoWrapperName = "LibCryptoWrapper";
        private const string _SslWrapperName = "LibSSLWrapper";
        private const string _CryptoNativeLibrary = "libcrypto";
        private const string _SslNativeLibrary = "libssl";
        private const string _SafeHandlBaseName = "SafeBaseHandle";
        private const string _SafeHandleReferenceName = "BaseReference";
        private const string _SafeHandleValueName = "BaseValue";
        private const string _SafeZeroHandleName = "SafeZeroHandle";
        private const string _SafeHandelBaseNamespaceName = "OpenSSL.Core.Interop.SafeHandles";
        private const string _NewSafeHandleAttributeName = "NewSafeHandle";
        private const string _DontTakeOwnershipAttributeName = "DontTakeOwnership";
        private const string _DontCheckReturnTypeName = "DontCheckReturnType";
        private const string _NativeClassName = "Native";
        private const string _IntegerVerificationMethodName = "ExpectSuccess";
        private const string _SafeHandleVerificationMethodName = "ExpectNonNull";
        private const string _ReturnValueLocalName = "ret";
        private const string _GeneratorAttributeClassName = "GeneratorDecaratorAttribute";
        private const string _GeneratoAttributesNamespaceName = "OpenSSL.Core.Interop.Attributes";
        private const string _PostConstructionMethodName = "PostConstruction";
        private const string _NewHandleSuffix = "NewSafeHandle";
        private const string _ReferenceHandleSuffix = "ReferenceSafeHandle";
        private const string _WrapperHandleSuffix = "WrapperSafeHandle";
        private const string _OutParameterNamePrefix = "out";
        private const string _PtrTypeName = "IntPtr";

        public void Initialize(GeneratorInitializationContext context)
        {
//#if DEBUG
//            if (!Debugger.IsAttached)
//            {
//                Debugger.Launch();
//            }
//#endif
            context.RegisterForSyntaxNotifications(this.GetSyntaxReceiver);
        }

        private ISyntaxReceiver GetSyntaxReceiver()
            => new GeneratorSyntaxReceiver();

        internal static NamespaceDeclarationSyntax FindParentNamespace(SyntaxNode node)
        {
            if(node is null)
            {
                throw new InvalidOperationException("Namespace not found");
            }

            if(node is NamespaceDeclarationSyntax ns)
            {
                return ns;
            }

            return FindParentNamespace(node.Parent);
        }

        public void Execute(GeneratorExecutionContext context)
        {
            GeneratorSyntaxReceiver syntaxReceiver = context.SyntaxReceiver as GeneratorSyntaxReceiver;

            HashSet<string> abstractSafeBaseHandles = new HashSet<string>();
            HashSet<ClassDeclarationSyntax> abstractSafeBaseHandlesSyntax = new HashSet<ClassDeclarationSyntax>();

            SemanticModel classModel;
            ISymbol symbol;
            INamedTypeSymbol namedTypeSymbol;
            foreach(ClassDeclarationSyntax classDeclarationSyntax in syntaxReceiver.SafeHandleCandidates)
            {
                classModel = context.Compilation.GetSemanticModel(classDeclarationSyntax.SyntaxTree);

                symbol = classModel.GetDeclaredSymbol(classDeclarationSyntax);

                if(symbol is null 
                    || symbol.Kind != SymbolKind.NamedType)
                {
                    continue;
                }

                namedTypeSymbol = (INamedTypeSymbol)symbol;

                //filter out all base classes
                if(namedTypeSymbol.Name.Equals(_SafeHandlBaseName)
                    || namedTypeSymbol.Name.Equals(_SafeHandleReferenceName)
                    || namedTypeSymbol.Name.Equals(_SafeHandleValueName)
                    || namedTypeSymbol.Name.Equals(_SafeZeroHandleName))
                {
                    continue;
                }

                //make sure it's abstract and a descendant of BaseReference or BaseValue
                if (namedTypeSymbol.IsAbstract
                    && (IsReferenceSafeHandle(namedTypeSymbol)
                        || IsValueSafeHandle(namedTypeSymbol)))
                {
                    abstractSafeBaseHandles.Add(namedTypeSymbol.Name);
                    abstractSafeBaseHandlesSyntax.Add(classDeclarationSyntax);
                }
            }

            SourceText concreteText = GenerateSafeHandleInstances
            (
                abstractSafeBaseHandlesSyntax,
                context.ParseOptions,
                "OpenSSL.Core.Interop.SafeHandles",
                "OpenSSL.Core.Interop.SafeHandles.SSL",
                "OpenSSL.Core.Interop.SafeHandles.Crypto",
                "OpenSSL.Core.Interop.SafeHandles.Crypto.EC",
                "OpenSSL.Core.Interop.SafeHandles.X509"
            );
            context.AddSource($"ConcreteSafeHandles.g.cs", concreteText);

            SemanticModel cryptoModel =  context
                .Compilation
                .GetSemanticModel
                (
                    syntaxReceiver.CryptoWrapper.SyntaxTree
                );

            SourceText cryptoText = GenerateInterfaceWrapper
            (
                _CryptoWrapperName,
                _CryptoNativeLibrary,
                syntaxReceiver.CryptoWrapper,
                cryptoModel,
                abstractSafeBaseHandles,
                context.ParseOptions,
                "OpenSSL.Core.Interop.SafeHandles",
                "OpenSSL.Core.Interop.SafeHandles.X509",
                "OpenSSL.Core.Interop.SafeHandles.Crypto",
                "OpenSSL.Core.Interop.SafeHandles.Crypto.EC"
            );
            context.AddSource($"{_CryptoWrapperName}.g.cs", cryptoText);

            SemanticModel sslModel = context
                .Compilation
                .GetSemanticModel
                (
                    syntaxReceiver.SslWrapper.SyntaxTree
                );

            SourceText sslText = GenerateInterfaceWrapper
            (
                _SslWrapperName,
                _SslNativeLibrary,
                syntaxReceiver.SslWrapper,
                sslModel,
                abstractSafeBaseHandles,
                context.ParseOptions,
                "OpenSSL.Core.Interop.SafeHandles",
                "OpenSSL.Core.Interop.SafeHandles.SSL",
                "OpenSSL.Core.Interop.SafeHandles.Crypto",
                "OpenSSL.Core.Interop.SafeHandles.X509"
            );
            context.AddSource($"{_SslWrapperName}.g.cs", sslText);

            SourceText factoryText = GenerateSafeHandleFactory
            (
                syntaxReceiver.FactoryWrapper,
                abstractSafeBaseHandlesSyntax,
                context.ParseOptions,
                "OpenSSL.Core.Interop.SafeHandles",
                "OpenSSL.Core.Interop.SafeHandles.SSL",
                "OpenSSL.Core.Interop.SafeHandles.Crypto",
                "OpenSSL.Core.Interop.SafeHandles.X509"
            );
            context.AddSource($"SafeHandleFactory.g.cs", factoryText);

            SemanticModel stackModel = context
                .Compilation
                .GetSemanticModel
                (
                    syntaxReceiver.StackWrapper.SyntaxTree
                );

            SourceText stackText = GenerateStackWrapper
            (
                _CryptoNativeLibrary,
                syntaxReceiver.StackWrapper,
                stackModel,
                abstractSafeBaseHandles,
                context.ParseOptions,
                "OpenSSL.Core.Interop.SafeHandles"
            );
            context.AddSource($"StackWrapper.g.cs", stackText);

            //string src = cryptoText.ToString();
            //src = sslText.ToString();
            //src = concreteText.ToString();
            //src = factoryText.ToString();
            //src = stackText.ToString();
        }

        private static bool IsReferenceSafeHandle(INamedTypeSymbol namedTypedSymbol)
        {
            if (namedTypedSymbol is null)
            {
                return false;
            }

            if (string.Equals(namedTypedSymbol.Name, _SafeHandleReferenceName)
                && string.Equals(namedTypedSymbol.ContainingNamespace.ToString(), _SafeHandelBaseNamespaceName))
            {
                return true;
            }

            return IsReferenceSafeHandle(namedTypedSymbol.BaseType);
        }

        private static bool IsValueSafeHandle(INamedTypeSymbol namedTypedSymbol)
        {
            if (namedTypedSymbol is null)
            {
                return false;
            }

            if (string.Equals(namedTypedSymbol.Name, _SafeHandleValueName)
                && string.Equals(namedTypedSymbol.ContainingNamespace.ToString(), _SafeHandelBaseNamespaceName))
            {
                return true;
            }

            return IsValueSafeHandle(namedTypedSymbol.BaseType);
        }

        private static bool IsSafeHandle
        (
            TypeSyntax originalTypeSyntax,
            SemanticModel semanticModel
        )
        {
            //if ref, it will never be a safehandle
            if (originalTypeSyntax is RefTypeSyntax)
            {
                return false;
            }

            SymbolInfo symbolInfo = semanticModel.GetSymbolInfo(originalTypeSyntax);

            if(symbolInfo.Symbol is null
                || symbolInfo.Symbol.Kind != SymbolKind.NamedType)
            {
                return false;
            }

            return IsSafeHandle((INamedTypeSymbol)symbolInfo.Symbol);
        }

        private static bool IsSafeHandle(INamedTypeSymbol namedTypedSymbol)
        {
            if(namedTypedSymbol is null)
            {
                return false;
            }

            if(string.Equals(namedTypedSymbol.Name, _SafeHandlBaseName)
                && string.Equals(namedTypedSymbol.ContainingNamespace.ToString(), _SafeHandelBaseNamespaceName))
            {
                return true;
            }

            return IsSafeHandle(namedTypedSymbol.BaseType);
        }

        private static TypeSyntax GenerateConcreteSafeHandleTypeName
        (
            TypeSyntax typeSyntax,
            (bool takeOwnership, bool isNew) modifiers
        )
        {
            string name;
            string suffix = string.Empty;

            if (typeSyntax is GenericNameSyntax genericNameSyntax)
            {
                name = genericNameSyntax.Identifier.WithoutTrivia().ToString();
                suffix = genericNameSyntax.TypeArgumentList.WithoutTrivia().ToString();
            }
            else
            {
                name = typeSyntax.WithoutTrivia().ToString();
            }

            if (modifiers.takeOwnership && modifiers.isNew)
            {
                name = string.Concat(name, _NewHandleSuffix);
            }
            else if(modifiers.takeOwnership)
            {
                name = string.Concat(name, _ReferenceHandleSuffix);
            }
            else
            {
                name = string.Concat(name, _WrapperHandleSuffix);
            }

            name = string.Concat(name, suffix);

            return SyntaxFactory.ParseName(name);
        }

        private static string GetSafeHandleTypeNameWithoutGenericTypeList
        (
            TypeSyntax typeSyntax
        )
        {
            if (typeSyntax is GenericNameSyntax genericNameSyntax)
            {
                return genericNameSyntax.Identifier.WithoutTrivia().ToString();
            }
            else
            {
                return typeSyntax.WithoutTrivia().ToString();
            }
        }

        private static TypeSyntax CreateConcreteSafeHandleType
        (
            TypeSyntax originalTypeSyntax,
            SemanticModel semanticModel,
            SyntaxList<AttributeListSyntax> symbolAttributes,
            ISet<string> abstractSafeBaseHandles,
            bool isNativeCall
        )
        {
            //if ref, it will never be a safehandle
            if(originalTypeSyntax is RefTypeSyntax refTypeSyntax)
            {
                return originalTypeSyntax;
            }

            string name = GetSafeHandleTypeNameWithoutGenericTypeList(originalTypeSyntax);

            //if native and generic type, return IntPtr
            if(isNativeCall
                && ContainsGenericTypeParameter(originalTypeSyntax, semanticModel, out _))
            {
                return SyntaxFactory.ParseName(_PtrTypeName);
            }
            //if known (!) abstract (!) safe handle type, construct concrete type
            else if (abstractSafeBaseHandles.Contains(name))
            {
                (bool takeOwnership, bool isNew) concreteTypeName;

                if (symbolAttributes.Any(x => x.Attributes.Any(y => string.Equals(y.Name.ToString(), _NewSafeHandleAttributeName))))
                {
                    concreteTypeName = (true, true);
                }
                else if (symbolAttributes.Any(x => x.Attributes.Any(y => string.Equals(y.Name.ToString(), _DontTakeOwnershipAttributeName))))
                {
                    concreteTypeName = (false, false);
                }
                else
                {
                    concreteTypeName = (true, false);
                }

                return GenerateConcreteSafeHandleTypeName(originalTypeSyntax, concreteTypeName);
            }
            //else return the original type
            else
            {
                return originalTypeSyntax;
            }
        }

        private static bool IsGeneratorAttribute(INamedTypeSymbol namedTypedSymbol)
        {
            if (namedTypedSymbol is null)
            {
                return false;
            }

            if (string.Equals(namedTypedSymbol.Name, _GeneratorAttributeClassName)
                && string.Equals(namedTypedSymbol.ContainingNamespace.ToString(), _GeneratoAttributesNamespaceName))
            {
                return true;
            }

            return IsGeneratorAttribute(namedTypedSymbol.BaseType);
        }

        private static SyntaxList<AttributeListSyntax> GenerateAttributesWithoutGeneratorAttributes
        (
            SyntaxList<AttributeListSyntax> originalAttributes,
            SemanticModel semanticModel
        )
        {
            bool added = false;
            AttributeListSyntax attributeList = SyntaxFactory.AttributeList();
            SyntaxList<AttributeListSyntax> newAttributes = SyntaxFactory.List<AttributeListSyntax>();
            SymbolInfo symbolInfo;

            foreach(AttributeSyntax attribute in originalAttributes.SelectMany(x => x.Attributes))
            {
                symbolInfo = semanticModel.GetSymbolInfo(attribute.Name);

                if(symbolInfo.Symbol is not null
                    && symbolInfo.Symbol.Kind == SymbolKind.Method
                    && IsGeneratorAttribute(((IMethodSymbol)symbolInfo.Symbol).ContainingType))
                {
                    continue;
                }

                added = true;

                attributeList = attributeList.AddAttributes(attribute.WithoutTrivia());
            }

            if(added)
            {
                newAttributes = newAttributes.Add(attributeList);
            }

            return newAttributes;
        }

        private static bool HasSupportedVerificationType
        (
            TypeSyntax typeSyntax,
            IdentifierNameSyntax localName,
            SemanticModel semanticModel,
            out InvocationExpressionSyntax verificationInvocation,
            out InvocationExpressionSyntax postConstructionInvocation
        )
        {
            IdentifierNameSyntax methodName;

            if (string.Equals(typeSyntax.ToString(), "int"))
            {
                methodName = SyntaxFactory.IdentifierName(_IntegerVerificationMethodName);

                postConstructionInvocation = null;
            }
            else if (IsSafeHandle(typeSyntax, semanticModel))
            {
                methodName = SyntaxFactory.IdentifierName(_SafeHandleVerificationMethodName);

                postConstructionInvocation = GeneratePostConstructionMethod
                (
                    localName
                );
            }
            else if (ContainsGenericTypeParameter(typeSyntax, semanticModel, out _))
            {
                methodName = SyntaxFactory.IdentifierName(_SafeHandleVerificationMethodName);

                postConstructionInvocation = GeneratePostConstructionMethod
                (
                    localName
                );
            }
            else
            {
                verificationInvocation = null;
                postConstructionInvocation = null;

                return false;
            }

            verificationInvocation = GenerateVerificationMethod
            (
                localName,
                methodName
            );

            return true;
        }

        private static InvocationExpressionSyntax GenerateVerificationMethod
        (

            IdentifierNameSyntax localName,
            IdentifierNameSyntax methodName
        )
        {
            return SyntaxFactory.InvocationExpression
            (
                SyntaxFactory.MemberAccessExpression
                (
                    SyntaxKind.SimpleMemberAccessExpression,
                    SyntaxFactory.IdentifierName(_NativeClassName),
                    methodName
                ),
                SyntaxFactory.ArgumentList
                (
                    SyntaxFactory.SeparatedList<ArgumentSyntax>
                    (
                        new ArgumentSyntax[]
                        {
                            SyntaxFactory.Argument
                            (
                                localName
                            )
                        }
                    )
                )
            );
        }

        private static InvocationExpressionSyntax GeneratePostConstructionMethod
        (
            IdentifierNameSyntax localName
        )
        {
            return SyntaxFactory.InvocationExpression
            (
                SyntaxFactory.MemberAccessExpression
                (
                    SyntaxKind.SimpleMemberAccessExpression,
                    localName,
                    SyntaxFactory.IdentifierName(_PostConstructionMethodName)
                ),
                SyntaxFactory.ArgumentList()
            );
        }

        private static bool ContainsGenericTypeParameter
        (
            TypeSyntax typeSyntax,
            SemanticModel stackModel,
            out bool isTypeParameter
        )
        {
            isTypeParameter = false;

            //EVERY generic, not just SafeStackHandle
            if (typeSyntax is GenericNameSyntax genericNameSyntax)
            {
                return true;
            }

            ISymbol symbol;
            SymbolInfo symbolInfo = stackModel.GetSymbolInfo(typeSyntax);

            if ((symbol = symbolInfo.Symbol) is null)
            {
                return false;
            }

            if (symbol.Kind == SymbolKind.TypeParameter)
            {
                isTypeParameter = true;
                return true;
            }

            return false;
        }
    }
}
