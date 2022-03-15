using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Diagnostics;
using System.Collections.Immutable;

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Text;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace OpenSSL.Core.Generator
{
    /* TODO
     * Make all safe handle classes partial abstract and add constructors through generator
     */
    [Generator]
    public partial class WrapperGenerator : IIncrementalGenerator
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
        private const string _TakeOwnershipAttributeName = "TakeOwnership";
        private const string _DontVerifyTypeName = "DontVerifyType";
        private const string _NativeClassName = "Native";
        private const string _IntegerVerificationMethodName = "ExpectSuccess";
        private const string _SafeHandleVerificationMethodName = "ExpectNonNull";
        private const string _ReturnValueLocalName = "ret";
        private const string _GeneratorAttributeClassName = "GeneratorDecaratorAttribute";
        private const string _GeneratoAttributesNamespaceName = "OpenSSL.Core.Interop.Attributes";
        private const string _TakeOwnershipHandleSuffix = "TakeOwnershipSafeHandle";
        private const string _WrapperHandleSuffix = "WrapperSafeHandle";
        private const string _OutParameterNamePrefix = "out";
        private const string _PtrTypeName = "IntPtr";

        private const string _StackWrapperInterfaceName = "IStackWrapper";
        private const string _SslWrapperInterfaceName = "ILibSSLWrapper";
        private const string _CryptoWrapperInterfaceName = "ILibCryptoWrapper";
        private const string _SafeHandleFactoryInterfaceName = "ISafeHandleFactory";
        private const string _SafeHandlesNamespaceName = "OpenSSL.Core.Interop.SafeHandles";

        public void Initialize(IncrementalGeneratorInitializationContext context)
        {
//#if DEBUG
//            if (!Debugger.IsAttached)
//            {
//                Debugger.Launch();
//            }
//#endif

            //get all (abstract) safe handle types
            IncrementalValuesProvider<ClassDeclarationSyntax> abstractSafeHandles =
                context.SyntaxProvider.CreateSyntaxProvider
            (
                IsSafeHandleCandidate,
                TransformSafeHandleCandidate
            )
            .Where(static x => x is not null);

            //get all wrapper interfaces
            IncrementalValuesProvider<(InterfaceDeclarationSyntax, SemanticModel)> wrapperInterfaces =
                context.SyntaxProvider.CreateSyntaxProvider
            (
                IsWrapperInterface,
                TransformWrapperInterface
            );

            context.RegisterSourceOutput
            (
                abstractSafeHandles.Collect(),
                ExecuteConcreteSafeHandleTypeGeneration
            );

            context.RegisterSourceOutput
            (
                wrapperInterfaces
                    //combine with all abstract safe handles
                    .Combine(abstractSafeHandles.Collect().WithComparer(new ClassCountComparer())),
                ExecuteWrapperInterfaceGenerator
            );
        }

        //only check lengths
        private class ClassCountComparer : IEqualityComparer<ImmutableArray<ClassDeclarationSyntax>>
        {
            public bool Equals(ImmutableArray<ClassDeclarationSyntax> x, ImmutableArray<ClassDeclarationSyntax> y)
                => x.Length == y.Length;

            public int GetHashCode(ImmutableArray<ClassDeclarationSyntax> obj)
                => 0;
        }

        private static bool IsSafeHandleCandidate
        (
            SyntaxNode syntaxNode,
            CancellationToken cancellationToken
        )
        {
            NamespaceDeclarationSyntax namespaceDeclaration;

            //create a list of BaseRefernce or BaseValue candidates
            if (syntaxNode is ClassDeclarationSyntax classDeclaration
                && (namespaceDeclaration = FindParentNamespace(classDeclaration)) is not null
                && namespaceDeclaration.Name.ToString().Contains(_SafeHandlesNamespaceName))
            {
                return true;
            }

            return false;
        }

        private static ClassDeclarationSyntax TransformSafeHandleCandidate
        (
            GeneratorSyntaxContext generatorSyntaxContext,
            CancellationToken cancellationToken
        )
        {
            SemanticModel classModel = generatorSyntaxContext.SemanticModel;
            ISymbol symbol;
            INamedTypeSymbol namedTypeSymbol;
            SyntaxNode syntaxNode = generatorSyntaxContext.Node;

            symbol = classModel.GetDeclaredSymbol(syntaxNode);

            if (symbol is null
                || symbol.Kind != SymbolKind.NamedType)
            {
                return null;
            }

            namedTypeSymbol = (INamedTypeSymbol)symbol;

            //filter out all base classes
            if (namedTypeSymbol.Name.Equals(_SafeHandlBaseName)
                || namedTypeSymbol.Name.Equals(_SafeHandleReferenceName)
                || namedTypeSymbol.Name.Equals(_SafeHandleValueName)
                || namedTypeSymbol.Name.Equals(_SafeZeroHandleName))
            {
                return null;
            }

            //make sure it's abstract and a descendant of BaseReference or BaseValue
            if (namedTypeSymbol.IsAbstract
                && (IsReferenceSafeHandle(namedTypeSymbol)
                    || IsValueSafeHandle(namedTypeSymbol)))
            {
                return (ClassDeclarationSyntax)syntaxNode;
            }

            return null;
        }

        private static void ExecuteConcreteSafeHandleTypeGeneration
        (
            SourceProductionContext sourceProductionContext,
            ImmutableArray<ClassDeclarationSyntax> abstractSafeBaseHandlesSyntax
        )
        {
            SourceText concreteText = GenerateSafeHandleInstances
            (
                abstractSafeBaseHandlesSyntax,
                "OpenSSL.Core.Interop.SafeHandles",
                "OpenSSL.Core.Interop.SafeHandles.SSL",
                "OpenSSL.Core.Interop.SafeHandles.Crypto",
                "OpenSSL.Core.Interop.SafeHandles.Crypto.EC",
                "OpenSSL.Core.Interop.SafeHandles.X509"
            );

            sourceProductionContext.AddSource($"ConcreteSafeHandles.g.cs", concreteText);
        }

        //all interfaces dependant on the safe handles
        private static bool IsWrapperInterface
        (
            SyntaxNode syntaxNode,
            CancellationToken cancellationToken
        )
        {
            if (syntaxNode is InterfaceDeclarationSyntax interfaceDeclaration)
            {
                if (string.Equals(_SslWrapperInterfaceName, interfaceDeclaration.Identifier.Text))
                {
                    return true;
                }
                else if (string.Equals(_CryptoWrapperInterfaceName, interfaceDeclaration.Identifier.Text))
                {
                    return true;
                }
                else if (string.Equals(_StackWrapperInterfaceName, interfaceDeclaration.Identifier.Text))
                {
                    return true;
                }
                else if (string.Equals(_SafeHandleFactoryInterfaceName, interfaceDeclaration.Identifier.Text))
                {
                    return true;
                }
            }

            return false;
        }

        private static (InterfaceDeclarationSyntax, SemanticModel) TransformWrapperInterface
        (
            GeneratorSyntaxContext generatorSyntaxContext,
            CancellationToken cancellationToken
        )
            => ((InterfaceDeclarationSyntax)generatorSyntaxContext.Node, generatorSyntaxContext.SemanticModel);

        private static void ExecuteWrapperInterfaceGenerator
        (
            SourceProductionContext sourceProductionContext,
            ((InterfaceDeclarationSyntax, SemanticModel), ImmutableArray<ClassDeclarationSyntax>) tpl
        )
        {
            SourceText sourceText = null;
            string hintName = String.Empty;

            InterfaceDeclarationSyntax @interface = tpl.Item1.Item1;
            SemanticModel semanticModel = tpl.Item1.Item2;
            ICollection<ClassDeclarationSyntax> abstractSafeBaseHandlesSyntax = tpl.Item2;

            HashSet<string> abstractSafeBaseHandles = new HashSet<string>(abstractSafeBaseHandlesSyntax.Select(x => x.Identifier.WithoutTrivia().ValueText));

            if (string.Equals(_SslWrapperInterfaceName, @interface.Identifier.Text))
            {
                sourceText = GenerateInterfaceWrapper
                (
                    _SslWrapperName,
                    _SslNativeLibrary,
                    @interface,
                    semanticModel,
                    abstractSafeBaseHandles,
                    "OpenSSL.Core.Interop.SafeHandles",
                    "OpenSSL.Core.Interop.SafeHandles.SSL",
                    "OpenSSL.Core.Interop.SafeHandles.Crypto",
                    "OpenSSL.Core.Interop.SafeHandles.X509"
                );

                hintName = $"{_SslWrapperName}.g.cs";
            }
            else if (string.Equals(_CryptoWrapperInterfaceName, @interface.Identifier.Text))
            {
                sourceText = GenerateInterfaceWrapper
                (
                    _CryptoWrapperName,
                    _CryptoNativeLibrary,
                    @interface,
                    semanticModel,
                    abstractSafeBaseHandles,
                    "OpenSSL.Core.Interop.SafeHandles",
                    "OpenSSL.Core.Interop.SafeHandles.X509",
                    "OpenSSL.Core.Interop.SafeHandles.Crypto",
                    "OpenSSL.Core.Interop.SafeHandles.Crypto.EC"
                );

                hintName = $"{_CryptoWrapperName}.g.cs";
            }
            else if (string.Equals(_StackWrapperInterfaceName, @interface.Identifier.Text))
            {
                sourceText = GenerateInterfaceWrapper
                (
                    _StackWrapperClassName,
                    _CryptoNativeLibrary,
                    @interface,
                    semanticModel,
                    abstractSafeBaseHandles,
                    "OpenSSL.Core.Interop.SafeHandles"
                );

                hintName = $"StackWrapper.g.cs";
            }
            else if (string.Equals(_SafeHandleFactoryInterfaceName, @interface.Identifier.Text))
            {
                sourceText = GenerateSafeHandleFactory
                (
                    @interface,
                    abstractSafeBaseHandlesSyntax,
                    "OpenSSL.Core.Interop.SafeHandles",
                    "OpenSSL.Core.Interop.SafeHandles.SSL",
                    "OpenSSL.Core.Interop.SafeHandles.Crypto",
                    "OpenSSL.Core.Interop.SafeHandles.X509"
                );
                hintName = "SafeHandleFactory.g.cs";
            }

            if (sourceText is null)
            {
                return;
            }

            //string src = sourceText.ToString();

            sourceProductionContext.AddSource(hintName, sourceText);
        }

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
            bool takeOwnership
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

            if (takeOwnership)
            {
                name = string.Concat(name, _TakeOwnershipHandleSuffix);
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
                bool takeOwnership = false;

                if (symbolAttributes.Any(x => x.Attributes.Any(y => string.Equals(y.Name.ToString(), _TakeOwnershipAttributeName))))
                {
                    takeOwnership = true;
                }

                return GenerateConcreteSafeHandleTypeName(originalTypeSyntax, takeOwnership);
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
            out InvocationExpressionSyntax verificationInvocation
        )
        {
            IdentifierNameSyntax methodName;

            if (string.Equals(typeSyntax.ToString(), "int"))
            {
                methodName = SyntaxFactory.IdentifierName(_IntegerVerificationMethodName);
            }
            else if (IsSafeHandle(typeSyntax, semanticModel))
            {
                methodName = SyntaxFactory.IdentifierName(_SafeHandleVerificationMethodName);
            }
            else if (ContainsGenericTypeParameter(typeSyntax, semanticModel, out _))
            {
                methodName = SyntaxFactory.IdentifierName(_SafeHandleVerificationMethodName);
            }
            else
            {
                verificationInvocation = null;
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
