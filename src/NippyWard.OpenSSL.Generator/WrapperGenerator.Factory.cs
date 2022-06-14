using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Diagnostics;
using System.Collections.Immutable;

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Text;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace NippyWard.OpenSSL.Generator
{
    public partial class WrapperGenerator
    {
        private const string _SafeHandleFactoryName = "SafeHandleFactory";
        private const string _StackHandleIgnoreName = "SafeStackHandle";
        private const string _TypeName = "FullName";
        private const string _FactoryExceptionType = "NotImplementedException";

        private static SourceText GenerateSafeHandleFactory
        (
            InterfaceDeclarationSyntax factoryWrapper,
            ICollection<string> fullSafeHandleTypeNames,
            params string[] usings
        )
        {
            ClassDeclarationSyntax classDeclaration
                = SyntaxFactory.ClassDeclaration
                (
                    SyntaxFactory.Identifier(_SafeHandleFactoryName)
                )
                .AddModifiers
                (
                    SyntaxFactory.Token(SyntaxKind.InternalKeyword)
                )
                .AddBaseListTypes
                (
                    SyntaxFactory.SimpleBaseType
                    (
                        SyntaxFactory.ParseTypeName(factoryWrapper.Identifier.Text)
                    )
                )
                .NormalizeWhitespace()
                .AddMembers
                (
                    GenerateFactoryMethods
                    (
                        factoryWrapper,
                        fullSafeHandleTypeNames
                    ).ToArray()
                )
                .NormalizeWhitespace();

            //fetch the namespace name from the base
            NameSyntax ns = FindParentNamespace(factoryWrapper).Name;

            //then create the compilation unit
            SyntaxTree syntaxTree = CSharpSyntaxTree.Create
            (
                SyntaxFactory.CompilationUnit()
                    .AddUsings
                    (
                        SyntaxFactory.UsingDirective
                        (
                            SyntaxFactory.ParseName("System")
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
                        SyntaxFactory.NamespaceDeclaration
                        (
                            SyntaxFactory.Token(SyntaxKind.NamespaceKeyword)
                                .WithLeadingTrivia
                                (
                                    SyntaxFactory.TriviaList
                                    (
                                        SyntaxFactory.Trivia
                                        (
                                            SyntaxFactory.NullableDirectiveTrivia(SyntaxFactory.Token(SyntaxKind.EnableKeyword), true)
                                        ),
                                        SyntaxFactory.Trivia
                                        (
                                            SyntaxFactory.PragmaWarningDirectiveTrivia
                                            (
                                                SyntaxFactory.Token(SyntaxKind.DisableKeyword),
                                                SyntaxFactory.SeparatedList<ExpressionSyntax>
                                                (
                                                    new ExpressionSyntax[]
                                                    {
                                                        SyntaxFactory.IdentifierName("CS8603")
                                                    }
                                                ),
                                                true
                                            )
                                        )
                                    )
                                ),
                            ns,
                            SyntaxFactory.Token(SyntaxKind.OpenBraceToken),
                            default,
                            default,
                            default,
                            SyntaxFactory.Token(SyntaxKind.CloseBraceToken),
                            default
                        )
                            .AddMembers(classDeclaration)
                    )
                    .NormalizeWhitespace(),
                    CSharpParseOptions.Default,
                    "",
                    Encoding.Unicode
            );

            return syntaxTree.GetText();
        }

        private static IEnumerable<MethodDeclarationSyntax> GenerateFactoryMethods
        (
            InterfaceDeclarationSyntax factoryWrapper,
            IEnumerable<string> fullSafeHandleTypeNames
        )
        {
            string methodName;
            foreach(MethodDeclarationSyntax method in factoryWrapper.DescendantNodes().OfType<MethodDeclarationSyntax>())
            {
                methodName = method.Identifier.WithoutTrivia().ToString();
                if (methodName.Contains("TakeOwnership"))
                {
                    yield return GenerateTakOwnershipFactoryMethod(method, fullSafeHandleTypeNames);
                }
                else if (methodName.Contains("Wrapper"))
                {
                    yield return GenerateWrapperFactoryMethod(method, fullSafeHandleTypeNames);
                }
            }
        }

        private static MethodDeclarationSyntax GenerateTakOwnershipFactoryMethod
        (
            MethodDeclarationSyntax originalMethod,
            IEnumerable<string> fullSafeHandleTypeNames
        )
        {
            return GenerateFactoryMethod
            (
                originalMethod,
                fullSafeHandleTypeNames,
                _TakeOwnershipHandleSuffix
            );
        }

        private static MethodDeclarationSyntax GenerateWrapperFactoryMethod
        (
            MethodDeclarationSyntax originalMethod,
            IEnumerable<string> fullSafeHandleTypeNames
        )
        {
            return GenerateFactoryMethod
            (
                originalMethod,
                fullSafeHandleTypeNames,
                _WrapperHandleSuffix
            );
        }

        private static MethodDeclarationSyntax GenerateFactoryMethod
        (
            MethodDeclarationSyntax interfaceMethod,
            IEnumerable<string> fullSafeHandleTypeNames,
            string suffix
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
                interfaceMethod.TypeParameterList!.WithoutTrivia(),
                interfaceMethod.ParameterList.WithoutTrivia(),
                interfaceMethod.ConstraintClauses,
                GenerateFactoryBlock
                (
                    interfaceMethod.TypeParameterList!.Parameters.First(),
                    fullSafeHandleTypeNames,
                    suffix
                ),
                null
            )
            .NormalizeWhitespace();
        }

        private static BlockSyntax GenerateFactoryBlock
        (
            TypeParameterSyntax genericParameter,
            IEnumerable<string> fullSafeHandleTypeNames,
            string suffix
        )
        {
            return SyntaxFactory.Block
            (
                //first create the switch with the full type name of the generic
                SyntaxFactory.SwitchStatement
                (
                    SyntaxFactory.MemberAccessExpression
                    (
                        SyntaxKind.SimpleMemberAccessExpression,
                        SyntaxFactory.TypeOfExpression
                        (
                            SyntaxFactory.IdentifierName(genericParameter.Identifier)
                        ),
                        SyntaxFactory.IdentifierName(_TypeName)
                    )
                )
                .AddSections
                (
                    GenerateFactorySwitchSections
                    (
                        genericParameter,
                        fullSafeHandleTypeNames,
                        suffix
                    )
                    .ToArray()
                )
                .AddSections
                (
                    GenerateDefaultExceptionSwitchSection()
                )
            );
        }

        private static SwitchSectionSyntax GenerateDefaultExceptionSwitchSection()
        {
            return SyntaxFactory.SwitchSection
            (
                SyntaxFactory.List
                (
                    new SwitchLabelSyntax[]
                    {
                        SyntaxFactory.DefaultSwitchLabel()
                    }
                ),
                SyntaxFactory.List
                (
                    new StatementSyntax[]
                    {
                        SyntaxFactory.ExpressionStatement
                        (
                            SyntaxFactory.ThrowExpression
                            (
                                SyntaxFactory.ObjectCreationExpression
                                (
                                    SyntaxFactory.ParseName(_FactoryExceptionType)
                                )
                                .WithArgumentList
                                (
                                    SyntaxFactory.ArgumentList()
                                )
                            )
                        )
                    }
                )
            );
        }

        private static IEnumerable<SwitchSectionSyntax> GenerateFactorySwitchSections
        (
            TypeParameterSyntax genericParameter,
            IEnumerable<string> fullSafeHandleTypeNames,
            string suffix
        )
        {
            foreach(string abstractType in fullSafeHandleTypeNames)
            {
                yield return GenerateFactorySwitchSection(genericParameter, abstractType, suffix);
            }
        }

        private static SwitchSectionSyntax GenerateFactorySwitchSection
        (
            TypeParameterSyntax genericParameter,
            string fullSafeHandleTypeName,
            string suffix
        )
        {
            string className = fullSafeHandleTypeName.Split('.').Last();

            return SyntaxFactory.SwitchSection
            (
                SyntaxFactory.List
                (
                    new SwitchLabelSyntax[]
                    {
                        SyntaxFactory.CaseSwitchLabel
                        (
                            SyntaxFactory.LiteralExpression
                            (
                                SyntaxKind.StringLiteralExpression,
                                SyntaxFactory.Literal(fullSafeHandleTypeName)
                            )
                        )
                    }
                ),
                SyntaxFactory.List
                (
                    new StatementSyntax[]
                    {
                        SyntaxFactory.ReturnStatement
                        (
                            SyntaxFactory.BinaryExpression
                            (
                                SyntaxKind.AsExpression,
                                SyntaxFactory.ObjectCreationExpression
                                (
                                    SyntaxFactory.IdentifierName(string.Concat(className, suffix))
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
                                                    SyntaxFactory.IdentifierName(_PtrParamterName)
                                                )
                                            }
                                        )
                                    )
                                ),
                                SyntaxFactory.IdentifierName(genericParameter.Identifier)
                            )
                        )
                    }
                )
            );
        }
    }
}
