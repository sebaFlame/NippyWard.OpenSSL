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

namespace OpenSSL.Core.Generator
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
            ISet<ClassDeclarationSyntax> abstractSafeBaseHandlesSyntax,
            ParseOptions parseOptions,
            params string[] usings
        )
        {
            ClassDeclarationSyntax[] supportedSafeHandles = abstractSafeBaseHandlesSyntax
                .Where(x => !string.Equals(x.Identifier.WithoutTrivia().ToString(), _StackHandleIgnoreName))
                .ToArray();

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
                        supportedSafeHandles
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

        private static IEnumerable<MethodDeclarationSyntax> GenerateFactoryMethods
        (
            InterfaceDeclarationSyntax factoryWrapper,
            IEnumerable<ClassDeclarationSyntax> abstractSafeBaseHandles
        )
        {
            string methodName;
            foreach(MethodDeclarationSyntax method in factoryWrapper.DescendantNodes().OfType<MethodDeclarationSyntax>())
            {
                methodName = method.Identifier.WithoutTrivia().ToString();
                if (methodName.Contains("New"))
                {
                    yield return GenerateNewFactoryMethod(method, abstractSafeBaseHandles);
                }
                else if (methodName.Contains("Reference"))
                {
                    yield return GenerateReferenceFactoryMethod(method, abstractSafeBaseHandles);
                }
                else if (methodName.Contains("Wrapper"))
                {
                    yield return GenerateWrapperFactoryMethod(method, abstractSafeBaseHandles);
                }
            }
        }

        private static MethodDeclarationSyntax GenerateNewFactoryMethod
        (
            MethodDeclarationSyntax originalMethod,
            IEnumerable<ClassDeclarationSyntax> abstractSafeBaseHandles
        )
        {
            return GenerateFactoryMethod
            (
                originalMethod,
                abstractSafeBaseHandles,
                _NewHandleSuffix
            );
        }

        private static MethodDeclarationSyntax GenerateReferenceFactoryMethod
        (
            MethodDeclarationSyntax originalMethod,
            IEnumerable<ClassDeclarationSyntax> abstractSafeBaseHandles
        )
        {
            return GenerateFactoryMethod
            (
                originalMethod,
                abstractSafeBaseHandles,
                _ReferenceHandleSuffix
            );
        }

        private static MethodDeclarationSyntax GenerateWrapperFactoryMethod
        (
            MethodDeclarationSyntax originalMethod,
            IEnumerable<ClassDeclarationSyntax> abstractSafeBaseHandles
        )
        {
            return GenerateFactoryMethod
            (
                originalMethod,
                abstractSafeBaseHandles,
                _WrapperHandleSuffix
            );
        }

        private static MethodDeclarationSyntax GenerateFactoryMethod
        (
            MethodDeclarationSyntax interfaceMethod,
            IEnumerable<ClassDeclarationSyntax> abstractSafeBaseHandles,
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
                interfaceMethod.TypeParameterList.WithoutTrivia(),
                interfaceMethod.ParameterList.WithoutTrivia(),
                interfaceMethod.ConstraintClauses,
                GenerateFactoryBlock
                (
                    interfaceMethod.TypeParameterList.Parameters.First(),
                    abstractSafeBaseHandles,
                    suffix
                ),
                null
            )
            .NormalizeWhitespace();
        }

        private static BlockSyntax GenerateFactoryBlock
        (
            TypeParameterSyntax genericParameter,
            IEnumerable<ClassDeclarationSyntax> abstractSafeBaseHandles,
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
                        abstractSafeBaseHandles,
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
            IEnumerable<ClassDeclarationSyntax> abstractSafeBaseHandles,
            string suffix
        )
        {
            foreach(ClassDeclarationSyntax abstractType in abstractSafeBaseHandles)
            {
                yield return GenerateFactorySwitchSection(genericParameter, abstractType, suffix);
            }
        }

        private static SwitchSectionSyntax GenerateFactorySwitchSection
        (
            TypeParameterSyntax genericParameter,
            ClassDeclarationSyntax abstractType,
            string suffix
        )
        {
            string abstractTypeName = abstractType.Identifier.WithoutTrivia().ToString();

            string fullName = string.Concat
            (
                FindParentNamespace(abstractType).Name.WithoutTrivia().ToString(),
                ".",
                abstractTypeName
            );

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
                                SyntaxFactory.Literal(fullName)
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
                                    SyntaxFactory.IdentifierName(string.Concat(abstractTypeName, suffix))
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
