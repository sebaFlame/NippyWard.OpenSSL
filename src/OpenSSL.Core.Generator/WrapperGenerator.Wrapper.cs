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
        private static SourceText GenerateInterfaceWrapper
        (
            string className,
            string nativeLibrary,
            InterfaceDeclarationSyntax wrapperInterface,
            SemanticModel semanticModel,
            ISet<string> abstractSafeBaseHandles,
            ParseOptions parseOptions,
            params string[] usings
        )
        {
            ClassDeclarationSyntax classDeclaration
                = SyntaxFactory.ClassDeclaration
                (
                    SyntaxFactory.Identifier(className)
                )
                .AddModifiers
                (
                    SyntaxFactory.Token(SyntaxKind.InternalKeyword)
                )
                .AddBaseListTypes
                (
                    SyntaxFactory.SimpleBaseType
                    (
                        SyntaxFactory.ParseTypeName(wrapperInterface.Identifier.Text)
                    )
                )
                .NormalizeWhitespace()
                .AddMembers
                (
                    GenerateMethods
                    (
                        wrapperInterface,
                        semanticModel,
                        abstractSafeBaseHandles,
                        nativeLibrary
                    ).ToArray()
                )
                .NormalizeWhitespace();

            //fetch the namespace name from the base
            NameSyntax ns = FindParentNamespace(wrapperInterface).Name;

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
                            x =>
                            SyntaxFactory.UsingDirective
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

        private static IEnumerable<MethodDeclarationSyntax> GenerateMethods
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

        private static MethodDeclarationSyntax GenerateNativeMethod
        (
            MethodDeclarationSyntax interfaceMethod,
            SemanticModel semanticModel,
            ISet<string> abstractSafeBaseHandles,
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
                CreateConcreteSafeHandleType
                (
                    interfaceMethod.ReturnType,
                    semanticModel,
                    interfaceMethod.AttributeLists,
                    abstractSafeBaseHandles,
                    true
                )
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
                            x => SyntaxFactory.Parameter
                            (
                                GenerateAttributesWithoutGeneratorAttributes
                                (
                                    x.AttributeLists,
                                    semanticModel
                                ),
                                x.Modifiers,
                                x.Modifiers.Any(y => y.WithoutTrivia().ValueText.Equals("out"))
                                    || ContainsGenericTypeParameter(x.Type, semanticModel, out _)
                                    ? CreateConcreteSafeHandleType
                                    (
                                        x.Type,
                                        semanticModel,
                                        x.AttributeLists,
                                        abstractSafeBaseHandles,
                                        true
                                    )
                                    .WithoutTrivia()
                                    : x.Type.WithoutTrivia(),
                                ContainsGenericTypeParameter(x.Type, semanticModel, out _)
                                    ? SyntaxFactory.Identifier
                                    (
                                        string.Concat(_PtrNamePrefix, x.Identifier.WithoutTrivia())
                                    )
                                    : x.Identifier.WithoutTrivia(),
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

        private static MethodDeclarationSyntax GenerateImplementationMethod
        (
            MethodDeclarationSyntax interfaceMethod,
            SemanticModel semanticModel,
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
                interfaceMethod.TypeParameterList?.WithoutTrivia(),
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
                                    semanticModel
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
                GenerateBlockSyntax
                (
                    interfaceMethod,
                    semanticModel,
                    abstractSafeBaseHandles,
                    nativeMethodName
                ),
                null
            )
            .NormalizeWhitespace();
        }

        private static BlockSyntax GenerateBlockSyntax
        (
            MethodDeclarationSyntax interfaceMethod,
            SemanticModel semanticModel,
            ISet<string> abstractSafeBaseHandles,
            string nativeMethodName
        )
        {
            BlockSyntax blockSyntax = SyntaxFactory.Block();
            InvocationExpressionSyntax verificationExpression, postConstructionExpression;
            TypeSyntax concreteReturnType = null;

            SyntaxList<AttributeListSyntax> methodAttributes = interfaceMethod.AttributeLists;

            //generate the invocation method, declaring conrete safe handle types
            InvocationExpressionSyntax invocation = GenerateNativeInvocationMethod
            (
                interfaceMethod,
                semanticModel,
                abstractSafeBaseHandles,
                nativeMethodName
            );

            //first create locals for all generic type parameters
            //skipping out parameters, which are defined and assigned during invocation
            foreach (ParameterSyntax parameter in interfaceMethod.ParameterList.Parameters.Where
            (
                x => !x.Modifiers.Any(x => x.WithoutTrivia().ValueText.Equals("out"))
                    && ContainsGenericTypeParameter(x.Type, semanticModel, out _)
            ))
            {
                blockSyntax = blockSyntax.AddStatements
                (
                    SyntaxFactory.LocalDeclarationStatement
                    (
                        SyntaxFactory.VariableDeclaration
                        (
                            SyntaxFactory.ParseName(_PtrTypeName),
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

            //there is a return type, save the invocation into a local
            if (!string.Equals(interfaceMethod.ReturnType.WithoutTrivia().ToString(), "void"))
            {
                //create the concrete return type
                concreteReturnType = CreateConcreteSafeHandleType
                (
                    interfaceMethod.ReturnType,
                    semanticModel,
                    methodAttributes,
                    abstractSafeBaseHandles,
                    true
                )
                .WithoutTrivia();

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
                                        string.Equals(concreteReturnType.ToString(), _PtrTypeName)
                                            && !string.Equals(concreteReturnType.ToString(), interfaceMethod.ReturnType.WithoutTrivia().ToString())
                                            ? SyntaxFactory.Identifier(_PtrReturnValueLocalName)
                                            : SyntaxFactory.Identifier(_ReturnValueLocalName),
                                        null,
                                        SyntaxFactory.EqualsValueClause
                                        (
                                            interfaceMethod.ReturnType is RefTypeSyntax
                                                ? SyntaxFactory.RefExpression
                                                (
                                                    invocation
                                                )
                                                : invocation
                                        )
                                    )
                                }
                            )
                        )
                    )
                )
                .NormalizeWhitespace();
            }
            //else just execute the invocation
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

            LocalDeclarationStatementSyntax localDeclarationStatementSyntax;

            //check if a return type should be constructed
            if (AssignConcreteTypeFromPointer
            (
                interfaceMethod.ReturnType,
                SyntaxFactory.Identifier(_ReturnValueLocalName),
                SyntaxFactory.Identifier(_PtrReturnValueLocalName),
                semanticModel,
                methodAttributes,
                abstractSafeBaseHandles,
                interfaceMethod,
                out localDeclarationStatementSyntax
            ))
            {
                blockSyntax = blockSyntax.AddStatements
                (
                    localDeclarationStatementSyntax
                )
                .NormalizeWhitespace();
            }

            //check if any out paramters should be constructed
            foreach (ParameterSyntax parameter in interfaceMethod.ParameterList.Parameters.Where
            (
                x => x.Modifiers.Any(y => y.WithoutTrivia().ValueText.Equals("out"))
                        && ContainsGenericTypeParameter(x.Type, semanticModel, out _)
            ))
            {
                if (AssignConcreteTypeFromPointer
                (
                    parameter.Type,
                    SyntaxFactory.Identifier(GenerateOutArgumentName(parameter, semanticModel, false)),
                    SyntaxFactory.Identifier(GenerateOutArgumentName(parameter, semanticModel, true)),
                    semanticModel,
                    methodAttributes,
                    abstractSafeBaseHandles,
                    interfaceMethod,
                    out localDeclarationStatementSyntax
                ))
                {
                    blockSyntax = blockSyntax.AddStatements
                    (
                        localDeclarationStatementSyntax
                    )
                    .NormalizeWhitespace();
                }
            }

            List<InvocationExpressionSyntax> postConstructionMethods = new List<InvocationExpressionSyntax>();

            //check return type
            if (!methodAttributes.Any(x => x.Attributes.Any(y => string.Equals(y.Name.ToString(), _DontCheckReturnTypeName))))
            {
                if (concreteReturnType is not null
                    && HasSupportedVerificationType
                    (
                        interfaceMethod.ReturnType,
                        SyntaxFactory.IdentifierName(_ReturnValueLocalName),
                        semanticModel,
                        out verificationExpression,
                        out postConstructionExpression
                    ))
                {
                    blockSyntax = blockSyntax.AddStatements
                    (
                        SyntaxFactory.ExpressionStatement
                        (
                            verificationExpression
                        )
                    )
                    .NormalizeWhitespace();

                    if (postConstructionExpression is not null)
                    {
                        postConstructionMethods.Add(postConstructionExpression);
                    }
                }
            }

            //check safe handle and all IntPtr out parameter
            foreach (ParameterSyntax parameter in interfaceMethod.ParameterList.Parameters.Where
            (
                x => x.Modifiers.Any(y => y.WithoutTrivia().ValueText.Equals("out"))
                    && !x.AttributeLists.Any(x => x.Attributes.Any(y => string.Equals(y.Name.ToString(), _DontCheckReturnTypeName)))
                    && (IsSafeHandle(x.Type, semanticModel)
                        || ContainsGenericTypeParameter(x.Type, semanticModel, out _))
            ))
            {
                if (!HasSupportedVerificationType
                (
                    parameter.Type,
                    SyntaxFactory.IdentifierName(GenerateOutArgumentName(parameter, semanticModel, false)),
                    semanticModel,
                    out verificationExpression,
                    out postConstructionExpression
                ))
                {
                    continue;
                }

                blockSyntax = blockSyntax.AddStatements
                (
                    SyntaxFactory.ExpressionStatement
                    (
                        verificationExpression
                    )
                )
                .NormalizeWhitespace();

                if (postConstructionExpression is not null)
                {
                    postConstructionMethods.Add(postConstructionExpression);
                }
            }

            foreach (InvocationExpressionSyntax post in postConstructionMethods)
            {
                blockSyntax = blockSyntax.AddStatements
                (
                    SyntaxFactory.ExpressionStatement
                    (
                        post
                    )
                )
                .NormalizeWhitespace();
            }

            //assign concrete safe handle out parameters
            if (invocation.DescendantNodes().OfType<SingleVariableDesignationSyntax>().Any())
            {
                //find all safe handle out paramters
                foreach (ParameterSyntax parameter in interfaceMethod.ParameterList.Parameters.Where
                (
                    x => x.Modifiers.Any(x => x.WithoutTrivia().ValueText.Equals("out"))
                        && abstractSafeBaseHandles.Contains(GetSafeHandleTypeNameWithoutGenericTypeList(x.Type))
                ))
                {
                    blockSyntax = blockSyntax.AddStatements
                    (
                        SyntaxFactory.ExpressionStatement
                        (
                            SyntaxFactory.AssignmentExpression
                            (
                                SyntaxKind.SimpleAssignmentExpression,
                                SyntaxFactory.IdentifierName(parameter.Identifier.WithoutTrivia()),
                                SyntaxFactory.IdentifierName(GenerateOutArgumentName(parameter, semanticModel, false))
                            )
                        )
                    )
                    .NormalizeWhitespace();
                }
            }

            //if there is a return type, return the value
            if (concreteReturnType is not null)
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
        private static InvocationExpressionSyntax GenerateNativeInvocationMethod
        (
            MethodDeclarationSyntax interfaceMethod,
            SemanticModel semanticModel,
            ISet<string> abstractSafeBaseHandles,
            string nativeMethodName
        )
            => SyntaxFactory.InvocationExpression
            (
                SyntaxFactory.IdentifierName(nativeMethodName),
                SyntaxFactory.ArgumentList
                (
                    SyntaxFactory.SeparatedList
                    (
                        interfaceMethod.ParameterList.Parameters.Select
                        (
                            x => x.Modifiers.Any(x => x.WithoutTrivia().ValueText.Equals("out"))
                                ? GenerateOutArgument(x, semanticModel, abstractSafeBaseHandles)
                                : SyntaxFactory.Argument
                                (
                                    null,
                                    x.Modifiers.FirstOrDefault(),
                                    ContainsGenericTypeParameter(x.Type, semanticModel, out _)
                                        ? SyntaxFactory.IdentifierName
                                        (
                                            string.Concat(_PtrNamePrefix, x.Identifier.WithoutTrivia())
                                        )
                                        : SyntaxFactory.IdentifierName(x.Identifier.WithoutTrivia())
                                )
                        )
                    )
                )
            );

        private static ArgumentSyntax GenerateOutArgument
        (
            ParameterSyntax parameterSyntax,
            SemanticModel semanticModel,
            ISet<string> abstractSafeBaseHandles
        )
        {
            string name = GetSafeHandleTypeNameWithoutGenericTypeList(parameterSyntax.Type);

            //parameter contains an abstract safe handle type
            //declare a local
            if (abstractSafeBaseHandles.Contains(name))
            {
                //else declare a new local for the concrete type
                return SyntaxFactory.Argument
                (
                    null,
                    parameterSyntax.Modifiers.First(), //should always be single
                    SyntaxFactory.DeclarationExpression
                    (
                        CreateConcreteSafeHandleType
                        (
                            parameterSyntax.Type,
                            semanticModel,
                            parameterSyntax.AttributeLists,
                            abstractSafeBaseHandles,
                            true
                        ).WithoutTrivia(),
                        SyntaxFactory.SingleVariableDesignation
                        (
                            SyntaxFactory.Identifier(GenerateOutArgumentName(parameterSyntax, semanticModel, true))
                        )
                    )
                );

            }
            //construct a new argument
            else
            {
                return SyntaxFactory.Argument
                (
                    null,
                    parameterSyntax.Modifiers.First(), //should always be single
                    SyntaxFactory.IdentifierName(parameterSyntax.Identifier.WithoutTrivia())
                );
            }
        }

        private static string GenerateOutArgumentName
        (
            ParameterSyntax parameterSyntax,
            SemanticModel semanticModel,
            bool isNativeCall
        )
        {
            string name = GetSafeHandleTypeNameWithoutGenericTypeList(parameterSyntax.Type);

            //if the parameter is a SafeStackhandle
            //or a generic type parameter
            //return pointer out name
            if(isNativeCall
                && ContainsGenericTypeParameter(parameterSyntax.Type, semanticModel, out _))
            {
                return string.Concat
                (
                    _OutParameterNamePrefix,
                    _PtrNamePrefix,
                    parameterSyntax.Identifier.WithoutTrivia()
                );
            }
            //else return an out name
            else
            {
                return string.Concat
                (
                    _OutParameterNamePrefix,
                    parameterSyntax.Identifier.WithoutTrivia()
                );
            }
        }

        private static bool AssignConcreteTypeFromPointer
        (
            TypeSyntax typeSyntax,
            SyntaxToken localName,
            SyntaxToken ptrLocalName,
            SemanticModel semanticModel,
            SyntaxList<AttributeListSyntax> symbolAttributes,
            ISet<string> abstractSafeBaseHandles,
            MethodDeclarationSyntax interfaceMethod,
            out LocalDeclarationStatementSyntax localDeclaration
        )
        {
            //a new (concrete) safe handle should be created
            if (ContainsGenericTypeParameter
            (
                typeSyntax,
                semanticModel,
                out bool isTypeParameter
            ))
            {
                //it's a generic type parameter, call the factory
                if (isTypeParameter)
                {
                    if(!IsStackableTypeParameter(typeSyntax, semanticModel))
                    {
                        throw new NotSupportedException($"{typeSyntax.ToString()} not supported");
                    }

                    localDeclaration =  SyntaxFactory.LocalDeclarationStatement
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
                                        localName,
                                        null,
                                        SyntaxFactory.EqualsValueClause
                                        (
                                            GenerateStackableFactoryInvocation
                                            (
                                                interfaceMethod,
                                                ptrLocalName
                                            )
                                        )
                                    )
                                }
                            )
                        )
                    );

                    return true;
                }
                //else it's a generic safe handle type -> create concrete instance
                else
                {
                    TypeSyntax concreteReturnType = CreateConcreteSafeHandleType
                    (
                        typeSyntax,
                        semanticModel,
                        symbolAttributes,
                        abstractSafeBaseHandles,
                        false
                    ).WithoutTrivia();

                    localDeclaration =  SyntaxFactory.LocalDeclarationStatement
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
                                        localName,
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
                                                                SyntaxFactory.IdentifierName(ptrLocalName)
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
                    );

                    return true;
                }
            }

            localDeclaration = null;
            return false;
        }
    }
}
