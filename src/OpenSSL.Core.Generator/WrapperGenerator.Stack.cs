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
    public partial class WrapperGenerator
    {
        private const string _PtrNamePrefix = "ptr";
        private const string _PtrReturnValueLocalName = "ptrRet";
        private const string _GetHandleMethodName = "DangerousGetHandle";
        private const string _CreateStackableItemMethodName = "CreateStackableItem";
        private const string _SafeStackHandleName = "SafeStackHandle";
        private const string _StackWrapperClassName = "StackWrapper";
        private static string[] _StackableConstraints = new string[] { "SafeBaseHandle", "IStackable" };

        private static SourceText GenerateStackWrapper
        (
            string nativeLibrary,
            InterfaceDeclarationSyntax stackWrapper,
            SemanticModel stackModel,
            ISet<string> abstractSafeBaseHandles,
            ParseOptions parseOptions,
            params string[] usings)
        {
            ClassDeclarationSyntax classDeclaration
                = SyntaxFactory.ClassDeclaration
                (
                    SyntaxFactory.Identifier(_StackWrapperClassName)
                )
                .AddModifiers
                (
                    SyntaxFactory.Token(SyntaxKind.InternalKeyword)
                )
                .AddBaseListTypes
                (
                    SyntaxFactory.SimpleBaseType
                    (
                        SyntaxFactory.ParseTypeName(stackWrapper.Identifier.Text)
                    )
                )
                .NormalizeWhitespace()
                .AddMembers
                (
                    GenerateStackMethods
                    (
                        stackWrapper,
                        stackModel,
                        abstractSafeBaseHandles,
                        nativeLibrary
                    ).ToArray()
                )
                .NormalizeWhitespace();

            //fetch the namespace name from the base
            NameSyntax ns = FindParentNamespace(stackWrapper).Name;

            //then create the compilation unit
            SyntaxTree syntaxTree = CSharpSyntaxTree.Create
            (
                SyntaxFactory.CompilationUnit()
                    .AddUsings
                    (
                        SyntaxFactory.UsingDirective
                        (
                            SyntaxFactory.ParseName("System")
                        ),
                        SyntaxFactory.UsingDirective
                        (
                            SyntaxFactory.ParseName("System.Runtime.InteropServices")
                        )
                    )
                    .NormalizeWhitespace()
                    .AddUsings
                    (
                        usings.Select
                        (
                            x => SyntaxFactory.UsingDirective
                            (
                                SyntaxFactory.ParseName(x)
                            )
                        )
                        .ToArray()
                    )
                    .NormalizeWhitespace()
                    .AddMembers
                    (
                        SyntaxFactory.NamespaceDeclaration(ns)
                            .AddMembers(classDeclaration)
                    )
                    .NormalizeWhitespace(),
                    parseOptions as CSharpParseOptions,
                    "",
                    Encoding.Unicode
            );

            return syntaxTree.GetText();
        }

        private static IEnumerable<MethodDeclarationSyntax> GenerateStackMethods
        (
            InterfaceDeclarationSyntax wrapperInterface,
            SemanticModel semanticModel,
            ISet<string> abstractSafeBaseHandles,
            string nativeLibrary
        )
        {
            string nativeMethodName;
            foreach (MethodDeclarationSyntax method in wrapperInterface.DescendantNodes().OfType<MethodDeclarationSyntax>())
            {
                yield return GenerateNativeMethod
                (
                    method,
                    semanticModel,
                    abstractSafeBaseHandles,
                    nativeLibrary,
                    out nativeMethodName
                );
                yield return GenerateImplementationMethod
                (
                    method,
                    semanticModel,
                    abstractSafeBaseHandles,
                    nativeMethodName
                );
            }
        }

        private static bool IsStackableTypeParameter
        (
            TypeSyntax genericTypeParameter,
            SemanticModel semanticModel
         )
        {
            ISymbol symbol;
            SymbolInfo symbolInfo = semanticModel.GetSymbolInfo(genericTypeParameter);

            if ((symbol = symbolInfo.Symbol) is null)
            {
                return false;
            }

            if (symbol.Kind != SymbolKind.TypeParameter)
            {
                return false;
            }

            ITypeParameterSymbol typeSymbol = (ITypeParameterSymbol)symbol;

            return _StackableConstraints.All
            (
                x => typeSymbol.ConstraintTypes.Any(y => y.Name.Equals(x))
            );
        }

        private static InvocationExpressionSyntax GenerateStackableFactoryInvocation
        (
            MethodDeclarationSyntax interfaceMethod,
            SyntaxToken ptrLocalName
        )
            => SyntaxFactory.InvocationExpression
            (
                SyntaxFactory.MemberAccessExpression
                (
                    SyntaxKind.SimpleMemberAccessExpression,
                    SyntaxFactory.IdentifierName(_NativeClassName),
                    SyntaxFactory.GenericName
                    (
                        SyntaxFactory.Identifier(_CreateStackableItemMethodName),
                        SyntaxFactory.TypeArgumentList
                        (
                            SyntaxFactory.SeparatedList<TypeSyntax>
                            (
                                interfaceMethod.TypeParameterList.Parameters
                                    .Select(x => SyntaxFactory.IdentifierName(x.WithoutTrivia().Identifier))
                                    .ToArray()
                            )
                        )
                    )
                ),
                SyntaxFactory.ArgumentList
                (
                    SyntaxFactory.SeparatedList
                    (
                        new ArgumentSyntax[]
                        {
                            SyntaxFactory.Argument
                            (
                                SyntaxFactory.IdentifierName
                                (
                                    interfaceMethod.ParameterList.Parameters
                                        .Single(x => IsSafeStackHandleParameter(x))
                                        .Identifier
                                )
                            ),
                            SyntaxFactory.Argument
                            (
                                SyntaxFactory.IdentifierName(ptrLocalName)
                            )
                        }
                    )
                )
            );

        private static bool IsSafeStackHandleParameter
        (
            ParameterSyntax parameter
        )
            => parameter.Type is GenericNameSyntax genericSyntax
                 && string.Equals(genericSyntax.Identifier.ValueText, _SafeStackHandleName);

        /*
        private static IEnumerable<MethodDeclarationSyntax> GenerateStackMethods
        (
            InterfaceDeclarationSyntax stackWrapper,
            SemanticModel stackModel,
            ISet<string> abstractSafeBaseHandles,
            string nativeLibrary
        )
        {
            string nativeMethodName;

            foreach (MethodDeclarationSyntax interfaceMethod in stackWrapper.DescendantNodes().OfType<MethodDeclarationSyntax>())
            {

                //has generic type return or parameter
                if (IsGenericTypeMethod(interfaceMethod))
                {
                    yield return GenerateGenericNativeMethod
                    (
                        interfaceMethod,
                        stackModel,
                        nativeLibrary,
                        out nativeMethodName
                    );

                    yield return GenerateGenericImplementationMethod
                    (
                        interfaceMethod,
                        stackModel,
                        abstractSafeBaseHandles,
                        nativeMethodName
                    );
                }
                else
                {
                    yield return GenerateNativeMethod
                    (
                        interfaceMethod,
                        stackModel,
                        abstractSafeBaseHandles,
                        nativeLibrary,
                        out nativeMethodName
                    );

                    yield return GenerateImplementationMethod
                    (
                        interfaceMethod,
                        stackModel,
                        abstractSafeBaseHandles,
                        nativeMethodName
                    );
                }
            }
        }

        private static bool IsGenericTypeMethod
        (
            MethodDeclarationSyntax interfaceMethod
        )
            => interfaceMethod.TypeParameterList is not null;

        private static MethodDeclarationSyntax GenerateGenericNativeMethod
        (
            MethodDeclarationSyntax interfaceMethod,
            SemanticModel stackModel,
            string nativeLibrary,
            out string nativeMethodName
        )
        {
            nativeMethodName = $"{nativeLibrary}_{interfaceMethod.Identifier.ValueText}";

            return SyntaxFactory.MethodDeclaration
            (
                SyntaxFactory.List
                (
                    new AttributeListSyntax[]
                    {
                        SyntaxFactory.AttributeList
                        (
                            SyntaxFactory.SeparatedList
                            (
                                new AttributeSyntax[]
                                {
                                    SyntaxFactory.Attribute
                                    (
                                        SyntaxFactory.ParseName("DllImport"),
                                        SyntaxFactory.AttributeArgumentList
                                        (
                                            SyntaxFactory.SeparatedList
                                            (
                                                new AttributeArgumentSyntax[]
                                                {
                                                    SyntaxFactory.AttributeArgument
                                                    (
                                                        SyntaxFactory.LiteralExpression
                                                        (
                                                            SyntaxKind.StringLiteralExpression,
                                                            SyntaxFactory.Literal(nativeLibrary)
                                                        )
                                                    ),
                                                    SyntaxFactory.AttributeArgument
                                                    (
                                                        SyntaxFactory.NameEquals
                                                        (
                                                            SyntaxFactory.IdentifierName("EntryPoint")
                                                        ),
                                                        null,
                                                        SyntaxFactory.LiteralExpression
                                                        (
                                                            SyntaxKind.StringLiteralExpression,
                                                            SyntaxFactory.Literal(interfaceMethod.Identifier.ValueText)
                                                        )
                                                    )
                                                }
                                            )
                                        )
                                    )
                                }
                            )
                        )
                    }
                ),
                SyntaxFactory.TokenList
                (
                    SyntaxFactory.Token(SyntaxKind.PrivateKeyword),
                    SyntaxFactory.Token(SyntaxKind.StaticKeyword),
                    SyntaxFactory.Token(SyntaxKind.ExternKeyword)
                ),
                ContainsGenericTypeParameter(interfaceMethod.ReturnType, stackModel)
                    ? SyntaxFactory.ParseName("IntPtr")
                    : interfaceMethod.ReturnType.WithoutTrivia()
                .WithoutTrivia(),
                null,
                SyntaxFactory.Identifier(nativeMethodName),
                null,
                SyntaxFactory.ParameterList
                (
                    SyntaxFactory.SeparatedList
                    (
                        interfaceMethod.ParameterList.Parameters.Select
                        (
                            x => ContainsGenericTypeParameter(x.Type, stackModel)
                                ? SyntaxFactory.Parameter
                                (
                                    GenerateAttributesWithoutGeneratorAttributes
                                    (
                                        x.AttributeLists,
                                        stackModel
                                    ),
                                    x.Modifiers,
                                    SyntaxFactory.ParseName("IntPtr"),
                                    SyntaxFactory.Identifier
                                    (
                                        string.Concat(_PtrNamePrefix, x.Identifier)
                                    ),
                                    null
                                )
                                : SyntaxFactory.Parameter
                                (
                                    GenerateAttributesWithoutGeneratorAttributes
                                    (
                                        x.AttributeLists,
                                        stackModel
                                    ),
                                    x.Modifiers,
                                    x.Type.WithoutTrivia(),
                                    x.Identifier,
                                    null
                                )
                        )
                    )
                ),
                SyntaxFactory.List<TypeParameterConstraintClauseSyntax>(), //drop all generic constraints
                null,
                null,
                SyntaxFactory.Token(SyntaxKind.SemicolonToken)
            )
            .NormalizeWhitespace();
        }

        private static MethodDeclarationSyntax GenerateGenericImplementationMethod
        (
            MethodDeclarationSyntax interfaceMethod,
            SemanticModel stackModel,
            ISet<string> abstractSafeBaseHandles,
            string nativeMethodName
        )
        {
            return SyntaxFactory.MethodDeclaration
            (
                SyntaxFactory.List<AttributeListSyntax>(),
                SyntaxFactory.TokenList
                (
                    SyntaxFactory.Token(SyntaxKind.PublicKeyword)
                ),
                interfaceMethod.ReturnType.WithoutTrivia(),
                null,
                SyntaxFactory.Identifier(interfaceMethod.Identifier.ValueText),
                interfaceMethod.TypeParameterList.WithoutTrivia(),
                SyntaxFactory.ParameterList
                (
                    SyntaxFactory.SeparatedList
                    (
                        interfaceMethod.ParameterList.Parameters.Select
                        (
                            x => SyntaxFactory.Parameter
                            (
                                GenerateAttributesWithoutGeneratorAttributes
                                (
                                    x.AttributeLists,
                                    stackModel
                                ),
                                x.Modifiers,
                                x.Type.WithoutTrivia(),
                                x.Identifier.WithoutTrivia(),
                                null
                            )
                        )
                    )
                ),
                interfaceMethod.ConstraintClauses,
                GenerateGenericBlockSyntax
                (
                    interfaceMethod,
                    stackModel,
                    abstractSafeBaseHandles,
                    nativeMethodName
                ),
                null
            )
            .NormalizeWhitespace();
        }

        private static BlockSyntax GenerateGenericBlockSyntax
        (
            MethodDeclarationSyntax interfaceMethod,
            SemanticModel stackModel,
            ISet<string> abstractSafeBaseHandles,
            string nativeMethodName
        )
        {
            BlockSyntax blockSyntax = SyntaxFactory.Block();

            SyntaxList<AttributeListSyntax> methodAttributes = interfaceMethod.AttributeLists;
            bool hasReturnType = false;

            //generate the native invocation
            InvocationExpressionSyntax invocation = GenerateGenericNativeInvocationMethod
            (
                interfaceMethod,
                stackModel,
                nativeMethodName
            );

            //first create locals for all generic type parameters
            foreach (ParameterSyntax parameter in interfaceMethod.ParameterList.Parameters.Where
            (
                x => ContainsGenericTypeParameter(x.Type, stackModel)
            ))
            {
                blockSyntax = blockSyntax.AddStatements
                (
                    SyntaxFactory.LocalDeclarationStatement
                    (
                        SyntaxFactory.VariableDeclaration
                        (
                            SyntaxFactory.ParseName("IntPtr"),
                            SyntaxFactory.SeparatedList<VariableDeclaratorSyntax>
                            (
                                new VariableDeclaratorSyntax[]
                                {
                                    SyntaxFactory.VariableDeclarator
                                    (
                                        SyntaxFactory.Identifier(string.Concat(_PtrNamePrefix, parameter.Identifier)),
                                        null,
                                        SyntaxFactory.EqualsValueClause
                                        (
                                            SyntaxFactory.InvocationExpression
                                            (
                                                SyntaxFactory.MemberAccessExpression
                                                (
                                                    SyntaxKind.SimpleMemberAccessExpression,
                                                    SyntaxFactory.IdentifierName(parameter.Identifier),
                                                    SyntaxFactory.IdentifierName(_GetHandleMethodName)
                                                ),
                                                SyntaxFactory.ArgumentList()
                                            )
                                        )
                                    )
                                }
                            )
                        )
                    )
                )
                .NormalizeWhitespace();
            }

            //assign IntPTr for returntype
            if (ContainsGenericTypeParameter(interfaceMethod.ReturnType, stackModel))
            {
                hasReturnType = true;

                blockSyntax = blockSyntax.AddStatements
                (
                    SyntaxFactory.LocalDeclarationStatement
                    (
                        SyntaxFactory.VariableDeclaration
                        (
                            SyntaxFactory.ParseName("IntPtr"),
                            SyntaxFactory.SeparatedList<VariableDeclaratorSyntax>
                            (
                                new VariableDeclaratorSyntax[]
                                {
                                    SyntaxFactory.VariableDeclarator
                                    (
                                        SyntaxFactory.Identifier(_PtrReturnValueLocalName),
                                        null,
                                        SyntaxFactory.EqualsValueClause
                                        (
                                            invocation
                                        )
                                    )
                                }
                            )
                        )
                    )
                )
                .NormalizeWhitespace();
            }
            //or assign to type if the method has a return type
            else if (!string.Equals(interfaceMethod.ReturnType.WithoutTrivia().ToString(), "void"))
            {
                hasReturnType = true;

                blockSyntax = blockSyntax.AddStatements
                (
                    SyntaxFactory.LocalDeclarationStatement
                    (
                        SyntaxFactory.VariableDeclaration
                        (
                            interfaceMethod.ReturnType.WithoutTrivia(),
                            SyntaxFactory.SeparatedList<VariableDeclaratorSyntax>
                            (
                                new VariableDeclaratorSyntax[]
                                {
                                    SyntaxFactory.VariableDeclarator
                                    (
                                        SyntaxFactory.Identifier(_ReturnValueLocalName),
                                        null,
                                        SyntaxFactory.EqualsValueClause
                                        (
                                            invocation
                                        )
                                    )
                                }
                            )
                        )
                    )
                )
                .NormalizeWhitespace();
            }
            //or just execute the method
            else
            {
                blockSyntax = blockSyntax.AddStatements
                (
                    SyntaxFactory.ExpressionStatement
                    (
                        invocation
                    )
                );
            }

            TypeSyntax concreteReturnType = null;

            //a new stack safe handle should be created
            if (IsSafeHandle(interfaceMethod.ReturnType, stackModel))
            {
                concreteReturnType = CreateConcreteSafeHandleType
                (
                    interfaceMethod.ReturnType,
                    stackModel,
                    methodAttributes,
                    abstractSafeBaseHandles,
                    true
                ).WithoutTrivia();

                blockSyntax = blockSyntax.AddStatements
                (
                    SyntaxFactory.LocalDeclarationStatement
                    (
                        SyntaxFactory.VariableDeclaration
                        (
                            concreteReturnType,
                            SyntaxFactory.SeparatedList<VariableDeclaratorSyntax>
                            (
                                new VariableDeclaratorSyntax[]
                                {
                                    SyntaxFactory.VariableDeclarator
                                    (
                                        SyntaxFactory.Identifier(_ReturnValueLocalName),
                                        null,
                                        SyntaxFactory.EqualsValueClause
                                        (
                                            SyntaxFactory.ObjectCreationExpression
                                            (
                                                concreteReturnType
                                            )
                                            .WithArgumentList
                                            (
                                                SyntaxFactory.ArgumentList
                                                (
                                                    SyntaxFactory.SeparatedList
                                                    (
                                                        new ArgumentSyntax[]
                                                        {
                                                            SyntaxFactory.Argument
                                                            (
                                                                SyntaxFactory.IdentifierName(_PtrReturnValueLocalName)
                                                            )
                                                        }
                                                    )
                                                )
                                            )
                                        )
                                    )
                                }
                            )
                        )
                    )
                )
                .NormalizeWhitespace();
            }
            //a new stackable item should be create of type (TStackable)
            else if (ContainsGenericTypeParameter(interfaceMethod.ReturnType, stackModel))
            {
                concreteReturnType = interfaceMethod.ReturnType.WithoutTrivia();

                blockSyntax = blockSyntax.AddStatements
                (
                    SyntaxFactory.LocalDeclarationStatement
                    (
                        SyntaxFactory.VariableDeclaration
                        (
                            interfaceMethod.ReturnType.WithoutTrivia(),
                            SyntaxFactory.SeparatedList<VariableDeclaratorSyntax>
                            (
                                new VariableDeclaratorSyntax[]
                                {
                                    SyntaxFactory.VariableDeclarator
                                    (
                                        SyntaxFactory.Identifier(_ReturnValueLocalName),
                                        null,
                                        SyntaxFactory.EqualsValueClause
                                        (
                                            GenerateStackableFactoryInvocation
                                            (
                                                interfaceMethod
                                            )
                                        )
                                    )
                                }
                            )
                        )
                    )
                )
                .NormalizeWhitespace();
            }

            //check return type
            if (!methodAttributes.Any(x => x.Attributes.Any(y => string.Equals(y.Name.ToString(), _DontCheckReturnTypeName)))
                && HasSupportedGenericVerificationType
                (
                    interfaceMethod.ReturnType,
                    SyntaxFactory.IdentifierName(_ReturnValueLocalName),
                    stackModel,
                    out InvocationExpressionSyntax verificationInvocation,
                    out InvocationExpressionSyntax postConstructionInvocation      
            ))
            {
                blockSyntax = blockSyntax.AddStatements
                (
                    SyntaxFactory.ExpressionStatement
                    (
                        verificationInvocation
                    )
                )
                .NormalizeWhitespace();

                if (postConstructionInvocation is not null)
                {
                    blockSyntax = blockSyntax.AddStatements
                    (
                        SyntaxFactory.ExpressionStatement
                        (
                            postConstructionInvocation
                        )
                    )
                    .NormalizeWhitespace();
                }
            }

            //if there is a return type, return the value
            if (hasReturnType)
            {
                blockSyntax = blockSyntax.AddStatements
                (
                    SyntaxFactory.ReturnStatement
                    (
                        interfaceMethod.ReturnType is RefTypeSyntax
                        ? SyntaxFactory.RefExpression
                        (
                            SyntaxFactory.ParseName(_ReturnValueLocalName)
                        )
                        : SyntaxFactory.ParseName(_ReturnValueLocalName)
                    )
                );
            }

            return blockSyntax;
        }

        //generates a native invocation method containingg variable declarations
        private static InvocationExpressionSyntax GenerateGenericNativeInvocationMethod
        (
            MethodDeclarationSyntax interfaceMethod,
            SemanticModel stackModel,
            string nativeMethodName
        )
            => SyntaxFactory.InvocationExpression
            (
                SyntaxFactory.IdentifierName(nativeMethodName),
                SyntaxFactory.ArgumentList
                (
                    SyntaxFactory.SeparatedList
                    (
                        SyntaxFactory.SeparatedList
                        (
                            interfaceMethod.ParameterList.Parameters.Select
                            (
                                x => ContainsGenericTypeParameter(x.Type, stackModel)
                                    ? SyntaxFactory.Argument
                                    (
                                        SyntaxFactory.IdentifierName(string.Concat(_PtrNamePrefix, x.Identifier))
                                    )
                                    : SyntaxFactory.Argument
                                    (
                                        SyntaxFactory.IdentifierName(x.Identifier)
                                    )
                            )
                        )
                    )
                )
            );

        private static bool HasSupportedGenericVerificationType
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
            else if(ContainsGenericTypeParameter(typeSyntax, semanticModel))
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


        */
    }
}
