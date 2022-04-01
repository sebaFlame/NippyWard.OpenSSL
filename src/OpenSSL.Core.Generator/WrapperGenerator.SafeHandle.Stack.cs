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
        private static SourceText GenerateStackSafeHandleInstances
        (
            SafeStackHandleModel model,
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
                                GenerateConcreteSafeStackHandleTypes(model).ToArray()
                            )
                    )
                    .NormalizeWhitespace(),
                    CSharpParseOptions.Default,
                    "",
                    Encoding.Unicode
            );

            return syntaxTree.GetText();
        }

        private static IEnumerable<ClassDeclarationSyntax> GenerateConcreteSafeStackHandleTypes
        (
            SafeStackHandleModel model
        )
        {
            yield return GenerateTakeOwnershipSafeStackHandleType(model);
            yield return GenerateWrapperStackHandleType(model);
        }

        private static ClassDeclarationSyntax GenerateTakeOwnershipSafeStackHandleType
        (
            SafeStackHandleModel model
        )
        {
            return GenerateConcreteSafeStackHandleType(model, _TakeOwnershipHandleSuffix, true);
        }

        private static ClassDeclarationSyntax GenerateWrapperStackHandleType
        (
            SafeStackHandleModel model
        )
        {
            return GenerateConcreteSafeStackHandleType(model, _WrapperHandleSuffix, false);
        }

        private static ClassDeclarationSyntax GenerateConcreteSafeStackHandleType
        (
            SafeStackHandleModel model,
            string suffix,
            bool takeOwnership
        )
        {
            string className = string.Concat(model.Name, suffix);

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
                    SyntaxFactory.GenericName
                    (
                        SyntaxFactory.Identifier(model.Name),
                        SyntaxFactory.TypeArgumentList
                        (
                            SyntaxFactory.SeparatedList<TypeSyntax>
                            (
                                model.GenericTypeParameters
                                    .Select(x => SyntaxFactory.IdentifierName(x))
                                    .ToArray()
                            )
                        )
                    )
                )
            )
            .AddTypeParameterListParameters
            (
                model.GenericTypeParameters
                    .Select(x => SyntaxFactory.TypeParameter(x))
                    .ToArray()
            )
            .NormalizeWhitespace()
            //TODO: support for multiple generic type parameters
            .AddConstraintClauses
            (
                model.GenericTypeParameters
                    .Select
                    (
                        x => SyntaxFactory.TypeParameterConstraintClause(x)
                            .WithConstraints
                            (
                                SyntaxFactory.SeparatedList<TypeParameterConstraintSyntax>
                                (
                                    model.GenericTypeConstraints
                                        .Select(y => SyntaxFactory.TypeConstraint(SyntaxFactory.IdentifierName(y)))
                                        .ToArray()
                                )
                            )
                    )
                    .ToArray()
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
    }
}
