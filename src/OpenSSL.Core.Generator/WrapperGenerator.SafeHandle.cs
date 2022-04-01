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
        private const string _ConcreteNamespaceName = "OpenSSL.Core.Interop.SafeHandles";
        private const string _PtrParamterName = "ptr";

        private static SourceText GenerateSafeHandleInstances
        (
            ICollection<string> abstractSafeHandleTypes,
            params string[] usings
        )
        {
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
                        SyntaxFactory.NamespaceDeclaration(SyntaxFactory.ParseName(_ConcreteNamespaceName))
                            .AddMembers
                            (
                                GenerateConcreteSafeHandleTypes(abstractSafeHandleTypes).ToArray()
                            )
                    )
                    .NormalizeWhitespace(),
                    CSharpParseOptions.Default,
                    "",
                    Encoding.Unicode
            );

            return syntaxTree.GetText();
        }

        private static IEnumerable<ClassDeclarationSyntax> GenerateConcreteSafeHandleTypes
        (
            IEnumerable<string> abstractSafeHandleTypes
        )
        {
            foreach(string abstractSafeHandleType in abstractSafeHandleTypes)
            {
                yield return GenerateTakeOwnershipSafeHandleType(abstractSafeHandleType);
                yield return GenerateWrapperHandleType(abstractSafeHandleType);
            }
        }

        private static ClassDeclarationSyntax GenerateTakeOwnershipSafeHandleType
        ( 
            string abstractSafeHandleType
        )
        {
            return GenerateConcreteSafeHandleType(abstractSafeHandleType, _TakeOwnershipHandleSuffix, true);
        }

        private static ClassDeclarationSyntax GenerateWrapperHandleType
        (
            string abstractSafeHandleType
        )
        {
            return GenerateConcreteSafeHandleType(abstractSafeHandleType, _WrapperHandleSuffix, false);
        }

        private static ClassDeclarationSyntax GenerateConcreteSafeHandleType
        (
            string abstractSafeHandleType,
            string suffix,
            bool takeOwnership
        )
        {
            string className = string.Concat(abstractSafeHandleType, suffix);

            return SyntaxFactory.ClassDeclaration
            (
                SyntaxFactory.Identifier(className)
            )
            .AddModifiers
            (
                SyntaxFactory.Token(SyntaxKind.InternalKeyword)
            )
            .NormalizeWhitespace()
            .AddBaseListTypes
            (
                SyntaxFactory.SimpleBaseType
                (
                    SyntaxFactory.ParseTypeName(abstractSafeHandleType)
                )
            )
            .NormalizeWhitespace()
            .AddMembers
            (
                GenerateDefaultConstructor(className, takeOwnership)
                    .NormalizeWhitespace(),
                GeneratePointerConstructor(className, takeOwnership)
                    .NormalizeWhitespace()
            )
            .NormalizeWhitespace();
        }

        private static ConstructorDeclarationSyntax GenerateDefaultConstructor
        (
            string className,
            bool takeOwnership
        )
        {
            return SyntaxFactory.ConstructorDeclaration(className)
                .AddModifiers(SyntaxFactory.Token(SyntaxKind.PublicKeyword))
                .WithInitializer
                (
                    SyntaxFactory.ConstructorInitializer
                    (
                        SyntaxKind.BaseConstructorInitializer
                    )
                    .WithArgumentList
                    (
                        SyntaxFactory.ArgumentList
                        (
                            SyntaxFactory.SeparatedList<ArgumentSyntax>
                            (
                                new ArgumentSyntax[]
                                {
                                    SyntaxFactory.Argument
                                    (
                                        takeOwnership
                                            ? SyntaxFactory.LiteralExpression(SyntaxKind.TrueLiteralExpression)
                                            : SyntaxFactory.LiteralExpression(SyntaxKind.FalseLiteralExpression)
                                    )
                                }
                            )
                        )
                    )
                )
                .WithBody(SyntaxFactory.Block());
        }

        private static ConstructorDeclarationSyntax GeneratePointerConstructor
        (
            string className,
            bool takeOwnership
        )
        {
            return SyntaxFactory.ConstructorDeclaration(className)
                .AddModifiers(SyntaxFactory.Token(SyntaxKind.PublicKeyword))
                .WithParameterList
                (
                    SyntaxFactory.ParameterList
                    (
                        SyntaxFactory.SeparatedList<ParameterSyntax>
                        (
                            new ParameterSyntax[]
                            {
                                SyntaxFactory.Parameter
                                (
                                    SyntaxFactory.Identifier(_PtrParamterName)
                                )
                                .WithType(SyntaxFactory.ParseName("IntPtr"))
                            }
                        )
                    )
                )
                .WithInitializer
                (
                    SyntaxFactory.ConstructorInitializer
                    (
                        SyntaxKind.BaseConstructorInitializer
                    )
                    .WithArgumentList
                    (
                        SyntaxFactory.ArgumentList
                        (
                            SyntaxFactory.SeparatedList<ArgumentSyntax>
                            (
                                new ArgumentSyntax[]
                                {
                                    SyntaxFactory.Argument
                                    (
                                        SyntaxFactory.IdentifierName(_PtrParamterName)
                                    ),
                                    SyntaxFactory.Argument
                                    (
                                        takeOwnership
                                            ? SyntaxFactory.LiteralExpression(SyntaxKind.TrueLiteralExpression)
                                            : SyntaxFactory.LiteralExpression(SyntaxKind.FalseLiteralExpression)
                                    )
                                }
                            )
                        )
                    )
                )
                .WithBody(SyntaxFactory.Block());
        }
    }
}
