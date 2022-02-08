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
            ISet<ClassDeclarationSyntax> abstractSafeBaseHandles,
            ParseOptions parseOptions,
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
                                GenerateConcreteSafeHandleTypes(abstractSafeBaseHandles).ToArray()
                            )
                    )
                    .NormalizeWhitespace(),
                    parseOptions as CSharpParseOptions,
                    "",
                    Encoding.Unicode
            );

            return syntaxTree.GetText();
        }

        private static IEnumerable<ClassDeclarationSyntax> GenerateConcreteSafeHandleTypes
        (
            IEnumerable<ClassDeclarationSyntax> originalSafeHandles
        )
        {
            foreach(ClassDeclarationSyntax originalSafeHandle in originalSafeHandles)
            {
                yield return GenerateNewSafeHandleType(originalSafeHandle);
                yield return GenerateReferenceHandleType(originalSafeHandle);
                yield return GenerateWrapperHandleType(originalSafeHandle);
            }
        }

        private static ClassDeclarationSyntax GenerateNewSafeHandleType
        ( 
            ClassDeclarationSyntax originalSafeHandle
        )
        {
            return GenerateConcreteSafeHandleType(originalSafeHandle, _NewHandleSuffix, true, true);
        }

        private static ClassDeclarationSyntax GenerateReferenceHandleType
        (
            ClassDeclarationSyntax originalSafeHandle
        )
        {
            return GenerateConcreteSafeHandleType(originalSafeHandle, _ReferenceHandleSuffix, true, false);
        }

        private static ClassDeclarationSyntax GenerateWrapperHandleType
        (
            ClassDeclarationSyntax originalSafeHandle
        )
        {
            return GenerateConcreteSafeHandleType(originalSafeHandle, _WrapperHandleSuffix, false, false);
        }

        private static ClassDeclarationSyntax GenerateConcreteSafeHandleType
        (
            ClassDeclarationSyntax originalSafeHandle,
            string suffix,
            bool takeOwnership,
            bool isNew
        )
        {
            string className = string.Concat(originalSafeHandle.Identifier.WithoutTrivia().ToString(), suffix);

            ClassDeclarationSyntax classDeclarationSyntax = SyntaxFactory.ClassDeclaration
            (
                SyntaxFactory.Identifier(className)
            )
            .AddModifiers
            (
                SyntaxFactory.Token(SyntaxKind.InternalKeyword)
            )

            .NormalizeWhitespace();

            //if the type is generic, copy over all generic elements
            if(originalSafeHandle.TypeParameterList is not null)
            {
                classDeclarationSyntax = classDeclarationSyntax
                .AddBaseListTypes
                (
                    SyntaxFactory.SimpleBaseType
                    (
                        SyntaxFactory.GenericName
                        (
                            SyntaxFactory.Identifier(originalSafeHandle.Identifier.WithoutTrivia().ToString()),
                            SyntaxFactory.TypeArgumentList
                            (
                                SyntaxFactory.SeparatedList<TypeSyntax>
                                (
                                    originalSafeHandle.TypeParameterList.Parameters
                                        .Select(x => SyntaxFactory.IdentifierName(x.WithoutTrivia().Identifier))
                                        .ToArray()
                                )
                            )
                        )
                    )
                )
                .AddTypeParameterListParameters
                (
                    originalSafeHandle.TypeParameterList.Parameters
                        .Select(x => x.WithoutTrivia())
                        .ToArray()
                )
                .AddConstraintClauses
                (
                    originalSafeHandle.ConstraintClauses
                        .Select(x => x.WithoutTrivia())
                        .ToArray()
                );
            }
            else
            {
                classDeclarationSyntax = classDeclarationSyntax
                .AddBaseListTypes
                (
                    SyntaxFactory.SimpleBaseType
                    (
                        SyntaxFactory.ParseTypeName(originalSafeHandle.Identifier.WithoutTrivia().ToString())
                    )
                );
            }

            classDeclarationSyntax = classDeclarationSyntax
            .AddMembers
            (
                GenerateDefaultConstructor(className, takeOwnership, isNew)
                    .NormalizeWhitespace(),
                GeneratePointerConstructor(className, takeOwnership, isNew)
                    .NormalizeWhitespace()
            )
            .NormalizeWhitespace();

            return classDeclarationSyntax;
        }

        private static ConstructorDeclarationSyntax GenerateDefaultConstructor
        (
            string className,
            bool takeOwnership,
            bool isNew
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
                                    ),
                                    SyntaxFactory.Argument
                                    (
                                        isNew
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
            bool takeOwnership,
            bool isNew
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
                                    ),
                                    SyntaxFactory.Argument
                                    (
                                        isNew
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
