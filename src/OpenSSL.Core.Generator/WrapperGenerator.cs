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
        private const string _SafeStackHandleName = "SafeStackHandle";
        private const string _SafeHandelBaseNamespaceName = "OpenSSL.Core.Interop.SafeHandles";
        private const string _TakeOwnershipAttributeName = "TakeOwnership";
        private const string _DontVerifyTypeName = "DontVerifyType";
        private const string _NativeClassName = "Native";
        private const string _IntegerVerificationMethodName = "ExpectSuccess";
        private const string _SafeHandleVerificationMethodName = "ExpectNonNull";
        private const string _ReturnValueLocalName = "ret";
        private const string _DontVerifyAttributeName = "DontVerifyType";
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

            //get abstract safe handles (without stack handles)
            IncrementalValuesProvider<string> abstractSafeHandles =
                context.SyntaxProvider.CreateSyntaxProvider
            (
                IsSafeHandleCandidate,
                TransformSafeHandleCandidate
            )
            .Where(static x => x is not null);

            //register safe handle concrete type generation
            context.RegisterSourceOutput
            (
                abstractSafeHandles.Collect(),
                ExecuteConcreteSafeHandleTypeGeneration
            );

            //get abstract safe stack handles
            IncrementalValuesProvider<SafeStackHandleModel> abstractSafeStackHandles =
                context.SyntaxProvider.CreateSyntaxProvider
            (
                IsSafeHandleCandidate,
                TransformStackHandleCandidate
            )
            .Where(static x => x.HasValue)
            .Select(static (y, _) => y.Value);

            //register safe stack handle concrete type generations
            context.RegisterSourceOutput
            (
                abstractSafeStackHandles,
                ExecuteConcreteSafeStackHandleTypeGeneration
            );

            //get abstract safe handles (without stack handles)
            //as a list of full names
            IncrementalValuesProvider<string> fullNameAbstractSafeHandles =
                context.SyntaxProvider.CreateSyntaxProvider
            (
                IsSafeHandleCandidate,
                TransformFactorySafeHandle
            )
            .Where(static x => x is not null);

            //get factory interface
            IncrementalValuesProvider<InterfaceDeclarationSyntax> factoryInterface =
                context.SyntaxProvider.CreateSyntaxProvider
            (
                IsFactoryInteface,
                TransformFactoryInterface
            );

            //register factory generation
            context.RegisterSourceOutput
            (
                factoryInterface
                    .Combine(fullNameAbstractSafeHandles.Collect()),
                ExecuteFactoryInterfaceGenerator
            );

            //get all abstract safe handel types (including stack)
            IncrementalValuesProvider<SafeHandleModel> abstractAllSafeHandles =
                context.SyntaxProvider.CreateSyntaxProvider
            (
                IsSafeHandleCandidate,
                TransformSafeHandleCandidateForWrapper
            )
            .Where(static x => x.HasValue)
            .Select(static (x, _) => x.Value);

            //get all wrapper interfaces
            IncrementalValuesProvider<InterfaceDeclarationSyntax> wrapperInterfaces =
                context.SyntaxProvider.CreateSyntaxProvider
            (
                IsWrapperInterface,
                TransformWrapperInterface
            );

            context.RegisterSourceOutput
            (
                wrapperInterfaces
                    .Combine(abstractAllSafeHandles.Collect()),
                ExecuteWrapperInterfaceGenerator
            );
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

        private static bool IsPossibleSafeHandleSymbol
        (
            SyntaxNode syntaxNode,
            SemanticModel semanticModel,
            out INamedTypeSymbol namedTypeSymbol
        )
        {
            ISymbol symbol = semanticModel.GetDeclaredSymbol(syntaxNode);

            if (symbol is null
                || symbol.Kind != SymbolKind.NamedType)
            {
                namedTypeSymbol = null;
                return false;
            }

            namedTypeSymbol = (INamedTypeSymbol)symbol;

            //filter out all base classes
            if (namedTypeSymbol.Name.Equals(_SafeHandlBaseName)
                || namedTypeSymbol.Name.Equals(_SafeHandleReferenceName)
                || namedTypeSymbol.Name.Equals(_SafeHandleValueName)
                || namedTypeSymbol.Name.Equals(_SafeZeroHandleName))
            {
                return false;
            }

            //make sure it's abstract and a descendant of BaseReference or BaseValue
            if (namedTypeSymbol.IsAbstract
                && (IsReferenceSafeHandle(namedTypeSymbol)
                    || IsValueSafeHandle(namedTypeSymbol)))
            {
                return true;
            }

            return false;
        }

        private static string TransformSafeHandleCandidate
        (
            GeneratorSyntaxContext generatorSyntaxContext,
            CancellationToken cancellationToken
        )
        {
            SyntaxNode syntaxNode = generatorSyntaxContext.Node;

            if (!IsPossibleSafeHandleSymbol
            (
                syntaxNode,
                generatorSyntaxContext.SemanticModel,
                out INamedTypeSymbol namedTypeSymbol
            ))
            {
                return null;
            }

            //remove stack handles (generic)
            if(IsStackHandle(namedTypeSymbol))
            {
                return null;
            }

            return ((ClassDeclarationSyntax)syntaxNode).Identifier.WithoutTrivia().ValueText;
        }

        private static void ExecuteConcreteSafeHandleTypeGeneration
        (
            SourceProductionContext sourceProductionContext,
            ImmutableArray<string> abstractSafeHandleList
        )
        {
            SourceText concreteText = GenerateSafeHandleInstances
            (
                abstractSafeHandleList,
                "OpenSSL.Core.Interop.SafeHandles",
                "OpenSSL.Core.Interop.SafeHandles.SSL",
                "OpenSSL.Core.Interop.SafeHandles.Crypto",
                "OpenSSL.Core.Interop.SafeHandles.Crypto.EC",
                "OpenSSL.Core.Interop.SafeHandles.X509"
            );

            sourceProductionContext.AddSource($"ConcreteSafeHandles.g.cs", concreteText);
        }

        private static SafeStackHandleModel? TransformStackHandleCandidate
        (
            GeneratorSyntaxContext generatorSyntaxContext,
            CancellationToken cancellationToken
        )
        {
            SyntaxNode syntaxNode = generatorSyntaxContext.Node;

            if (!IsPossibleSafeHandleSymbol
            (
                syntaxNode,
                generatorSyntaxContext.SemanticModel,
                out INamedTypeSymbol namedTypeSymbol
            ))
            {
                return null;
            }

            //make sure it's abstract and a descendant of BaseReference or BaseValue
            if (IsStackHandle(namedTypeSymbol))
            {
                ClassDeclarationSyntax stackClass = ((ClassDeclarationSyntax)syntaxNode);

                return new SafeStackHandleModel
                (
                    stackClass.Identifier.WithoutTrivia().ValueText,
                    stackClass
                        .TypeParameterList
                        .DescendantNodes()
                        .OfType<TypeParameterSyntax>()
                        .Select(x => x.Identifier.WithoutTrivia().ValueText)
                        .ToArray(),
                    stackClass
                        .ConstraintClauses
                        .SelectMany(x => x.DescendantNodes().OfType<TypeConstraintSyntax>())
                        .Select(y => y.WithoutTrivia().ToString())
                        .ToArray()
                );
            }

            return null;
        }

        private static void ExecuteConcreteSafeStackHandleTypeGeneration
        (
            SourceProductionContext sourceProductionContext,
            SafeStackHandleModel safeStackModel
        )
        {
            SourceText concreteText = GenerateStackSafeHandleInstances
            (
                safeStackModel,
                "OpenSSL.Core.Interop.SafeHandles"
            );

            sourceProductionContext.AddSource($"ConcreteStackSafeHandles.g.cs", concreteText);
        }

        private static string TransformFactorySafeHandle
        (
            GeneratorSyntaxContext generatorSyntaxContext,
            CancellationToken cancellationToken
        )
        {
            SyntaxNode syntaxNode = generatorSyntaxContext.Node;

            if (!IsPossibleSafeHandleSymbol
            (
                syntaxNode,
                generatorSyntaxContext.SemanticModel,
                out INamedTypeSymbol namedTypeSymbol
            ))
            {
                return null;
            }

            //remove stack handles (generic)
            if (IsStackHandle(namedTypeSymbol))
            {
                return null;
            }

            ClassDeclarationSyntax @class = (ClassDeclarationSyntax)syntaxNode;

            return string.Concat
            (
                FindParentNamespace(@class).Name.WithoutTrivia().ToString(),
                ".",
                @class.Identifier.WithoutTrivia().ValueText
            );
        }

        private static SafeHandleModel? TransformSafeHandleCandidateForWrapper
        (
            GeneratorSyntaxContext generatorSyntaxContext,
            CancellationToken cancellationToken
        )
        {
            SyntaxNode syntaxNode = generatorSyntaxContext.Node;
            SemanticModel semanticModel = generatorSyntaxContext.SemanticModel;

            ISymbol symbol = semanticModel.GetDeclaredSymbol(syntaxNode);

            if (symbol is null
                || symbol.Kind != SymbolKind.NamedType)
            {
                return null;
            }

            INamedTypeSymbol namedTypeSymbol = (INamedTypeSymbol)symbol;

            //filter out all base classes
            if (namedTypeSymbol.Name.Equals(_SafeHandlBaseName)
                || namedTypeSymbol.Name.Equals(_SafeHandleReferenceName)
                || namedTypeSymbol.Name.Equals(_SafeHandleValueName)
                || namedTypeSymbol.Name.Equals(_SafeZeroHandleName))
            {
                return null;
            }

            //make sure it's abstract and a descendant of BaseReference or BaseValue
            if (IsReferenceSafeHandle(namedTypeSymbol)
                || IsValueSafeHandle(namedTypeSymbol))
            {
                ClassDeclarationSyntax @class = ((ClassDeclarationSyntax)syntaxNode);
                string name = @class.Identifier.WithoutTrivia().ValueText;

                return new SafeHandleModel(name, namedTypeSymbol.IsAbstract);
            }

            return null;
        }

        private static InterfaceDeclarationSyntax TransformFactoryInterface
        (
            GeneratorSyntaxContext generatorSyntaxContext,
            CancellationToken cancellationToken
        )
            => (InterfaceDeclarationSyntax)generatorSyntaxContext.Node;

        private static void ExecuteFactoryInterfaceGenerator
        (
            SourceProductionContext sourceProductionContext,
            (InterfaceDeclarationSyntax, ImmutableArray<string>) tpl
        )
        {
            InterfaceDeclarationSyntax @interface = tpl.Item1;
            ICollection<string> fullSafeHandleTypeNames = tpl.Item2;

            SourceText sourceText = GenerateSafeHandleFactory
            (
                @interface,
                fullSafeHandleTypeNames,
                "OpenSSL.Core.Interop.SafeHandles",
                "OpenSSL.Core.Interop.SafeHandles.SSL",
                "OpenSSL.Core.Interop.SafeHandles.Crypto",
                "OpenSSL.Core.Interop.SafeHandles.X509"
            );

            string hintName = "SafeHandleFactory.g.cs";

            sourceProductionContext.AddSource(hintName, sourceText);
        }

        private static InterfaceDeclarationSyntax TransformWrapperInterface
        (
            GeneratorSyntaxContext generatorSyntaxContext,
            CancellationToken cancellationToken
        )
            => (InterfaceDeclarationSyntax)generatorSyntaxContext.Node;

        private static bool IsFactoryInteface
        (
            SyntaxNode syntaxNode,
            CancellationToken cancellationToken
        )
        {
            if (syntaxNode is InterfaceDeclarationSyntax interfaceDeclaration
                && string.Equals(_SafeHandleFactoryInterfaceName, interfaceDeclaration.Identifier.Text))
            {
                return true;
            }

            return false;
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
            }

            return false;
        }

        private static void ExecuteWrapperInterfaceGenerator
        (
            SourceProductionContext sourceProductionContext,
            (InterfaceDeclarationSyntax, ImmutableArray<SafeHandleModel>) tpl
        )
        {
            SourceText sourceText = null;
            string hintName = String.Empty;
            InterfaceDeclarationSyntax @interface = tpl.Item1;
            ICollection<SafeHandleModel> safeHandles = tpl.Item2;

            if (string.Equals(_SslWrapperInterfaceName, @interface.Identifier.Text))
            {
                sourceText = GenerateInterfaceWrapper
                (
                    _SslWrapperName,
                    _SslNativeLibrary,
                    @interface,
                    safeHandles,
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
                    safeHandles,
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
                    safeHandles,
                    "OpenSSL.Core.Interop.SafeHandles"
                );

                hintName = $"StackWrapper.g.cs";
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

        private static bool IsStackHandle(INamedTypeSymbol namedTypedSymbol)
        {
            if (namedTypedSymbol is null)
            {
                return false;
            }

            if (string.Equals(namedTypedSymbol.Name, _SafeStackHandleName)
                && string.Equals(namedTypedSymbol.ContainingNamespace.ToString(), _SafeHandelBaseNamespaceName))
            {
                return true;
            }

            return IsStackHandle(namedTypedSymbol.BaseType);
        }

        private static bool IsSafeHandle
        (
            TypeSyntax originalTypeSyntax,
            ICollection<SafeHandleModel> safeHandles
        )
        {
            //if ref, it will never be a safehandle
            if (originalTypeSyntax is RefTypeSyntax)
            {
                return false;
            }

            string name = originalTypeSyntax.WithoutTrivia().ToString();

            return safeHandles.Any(x => x.Name.Equals(name));
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
            MethodDeclarationSyntax method,
            TypeSyntax originalTypeSyntax,
            SyntaxList<AttributeListSyntax> symbolAttributes,
            ICollection<SafeHandleModel> abstractSafeBaseHandles,
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
                && ContainsGenericTypeParameter(originalTypeSyntax, method.TypeParameterList, out _))
            {
                return SyntaxFactory.ParseName(_PtrTypeName);
            }
            //if known (!) abstract (!) safe handle type, construct concrete type
            else if (abstractSafeBaseHandles.Any(x => x.IsAbsract && x.Name.Equals(name)))
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

        private static bool IsGeneratorAttribute(string name)
        {
            return string.Equals(name, _DontVerifyAttributeName)
                    || string.Equals(name, _TakeOwnershipAttributeName);
        }

        private static SyntaxList<AttributeListSyntax> GenerateAttributesWithoutGeneratorAttributes
        (
            SyntaxList<AttributeListSyntax> originalAttributes
        )
        {
            bool added = false;
            AttributeListSyntax attributeList = SyntaxFactory.AttributeList();
            SyntaxList<AttributeListSyntax> newAttributes = SyntaxFactory.List<AttributeListSyntax>();
            SymbolInfo symbolInfo;

            foreach(AttributeSyntax attribute in originalAttributes.SelectMany(x => x.Attributes))
            {
                if(IsGeneratorAttribute(attribute.Name.WithoutTrivia().ToString()))
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
            MethodDeclarationSyntax method,
            TypeSyntax typeSyntax,
            IdentifierNameSyntax localName,
            ICollection<SafeHandleModel> abstractSafeBaseHandles,
            out InvocationExpressionSyntax verificationInvocation
        )
        {
            IdentifierNameSyntax methodName;

            if (string.Equals(typeSyntax.ToString(), "int"))
            {
                methodName = SyntaxFactory.IdentifierName(_IntegerVerificationMethodName);
            }
            else if (IsSafeHandle(typeSyntax, abstractSafeBaseHandles))
            {
                methodName = SyntaxFactory.IdentifierName(_SafeHandleVerificationMethodName);
            }
            else if (ContainsGenericTypeParameter(typeSyntax, method.TypeParameterList, out _))
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
            TypeParameterListSyntax typeParameters,
            out bool isTypeParameter
        )
        {
            isTypeParameter = false;

            //EVERY generic, not just SafeStackHandle
            if (typeSyntax is GenericNameSyntax genericNameSyntax)
            {
                return true;
            }

            if(typeParameters is null)
            {
                return false;
            }

            string name = typeSyntax.WithoutTrivia().ToString();

            //check if generic type parameter
            foreach(TypeParameterSyntax typeParameter in typeParameters.DescendantNodes().OfType<TypeParameterSyntax>())
            {
                if(string.Equals(typeParameter.Identifier.WithoutTrivia().ValueText, name))
                {
                    isTypeParameter = true;
                    return true;
                }
            }

            return false;
        }
    }
}
