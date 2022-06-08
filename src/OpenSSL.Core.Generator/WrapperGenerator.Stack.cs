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
        private const string _StackWrapperClassName = "StackWrapper";
        private static string[] _StackableConstraints = new string[] { "SafeBaseHandle", "IStackable" };

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
                                interfaceMethod.TypeParameterList!.Parameters
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

    }
}
