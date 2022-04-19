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
            ICollection<SafeHandleModel> safeHandles,
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
                        safeHandles,
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
                    CSharpParseOptions.Default,
                    "",
                    Encoding.Unicode
            );

            return syntaxTree.GetText();
        }

        private static IEnumerable<MethodDeclarationSyntax> GenerateMethods
        (
            InterfaceDeclarationSyntax wrapperInterface,
            ICollection<SafeHandleModel> safeHandles,
            string nativeLibrary
        )
        {
            string nativeMethodName;
            foreach (MethodDeclarationSyntax method in wrapperInterface.DescendantNodes().OfType<MethodDeclarationSyntax>())
            {
                yield return GenerateNativeMethod
                (
                    method,
                    safeHandles,
                    nativeLibrary,
                    out nativeMethodName
                );

                if (NeedsWindowsOverride(method))
                {
                    yield return GenerateNativeWindowsMethod
                    (
                        method,
                        safeHandles,
                        nativeLibrary,
                        nativeMethodName
                    );
                }

                yield return GenerateImplementationMethod
                (
                    method,
                    safeHandles,
                    nativeMethodName
                );
            }
        }

        private static MethodDeclarationSyntax GenerateNativeMethod
        (
            MethodDeclarationSyntax interfaceMethod,
            ICollection<SafeHandleModel> safeHandles,
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
                    interfaceMethod,
                    interfaceMethod.ReturnType,
                    interfaceMethod.AttributeLists,
                    safeHandles,
                    true,
                    false
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
                                    x.AttributeLists
                                ),
                                x.Modifiers,
                                x.Modifiers.Any(y => y.WithoutTrivia().ValueText.Equals("out"))
                                    || ContainsGenericTypeParameter(x.Type, interfaceMethod.TypeParameterList, out _)
                                    || NeedsWindowsOverride(x.AttributeLists)
                                    ? CreateConcreteSafeHandleType
                                    (
                                        interfaceMethod,
                                        x.Type,
                                        x.AttributeLists,
                                        safeHandles,
                                        true,
                                        false
                                    )
                                    .WithoutTrivia()
                                    : x.Type.WithoutTrivia(),
                                ContainsGenericTypeParameter(x.Type, interfaceMethod.TypeParameterList, out _)
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

        private static MethodDeclarationSyntax GenerateNativeWindowsMethod
        (
            MethodDeclarationSyntax interfaceMethod,
            ICollection<SafeHandleModel> safeHandles,
            string nativeLibrary,
            string nativeMethodName
        )
        {
            nativeMethodName = $"{nativeMethodName}{_WindowsMethodSuffix}";

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
                    interfaceMethod,
                    interfaceMethod.ReturnType,
                    interfaceMethod.AttributeLists,
                    safeHandles,
                    true,
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
                                    x.AttributeLists
                                ),
                                x.Modifiers,
                                x.Modifiers.Any(y => y.WithoutTrivia().ValueText.Equals("out"))
                                    || ContainsGenericTypeParameter(x.Type, interfaceMethod.TypeParameterList, out _)
                                    || NeedsWindowsOverride(x.AttributeLists)
                                    ? CreateConcreteSafeHandleType
                                    (
                                        interfaceMethod,
                                        x.Type,
                                        x.AttributeLists,
                                        safeHandles,
                                        true,
                                        true
                                    )
                                    .WithoutTrivia()
                                    : x.Type.WithoutTrivia(),
                                ContainsGenericTypeParameter(x.Type, interfaceMethod.TypeParameterList, out _)
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
            ICollection<SafeHandleModel> safeHandles,
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
                                    x.AttributeLists
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
                    safeHandles,
                    nativeMethodName
                ),
                null
            )
            .NormalizeWhitespace();
        }

        private static BlockSyntax GenerateBlockSyntax
        (
            MethodDeclarationSyntax interfaceMethod,
            ICollection<SafeHandleModel> safeHandles,
            string nativeMethodName
        )
        {
            BlockSyntax blockSyntax = SyntaxFactory.Block();
            InvocationExpressionSyntax verificationExpression, postConstructionExpression;
            TypeSyntax concreteReturnType = null;
            InvocationExpressionSyntax winInvocation = null;

            SyntaxList<AttributeListSyntax> methodAttributes = interfaceMethod.AttributeLists;

            bool needsWindowsOverride = NeedsWindowsOverride(interfaceMethod);

            //generate the invocation method, declaring conrete safe handle types
            InvocationExpressionSyntax invocation = GenerateNativeInvocationMethod
            (
                interfaceMethod,
                safeHandles,
                nativeMethodName,
                false
            );

            //generate a windows invocation with out parameter initialization
            if (needsWindowsOverride)
            {
                winInvocation = GenerateNativeInvocationMethod
                (
                    interfaceMethod,
                    safeHandles,
                    string.Concat(nativeMethodName, _WindowsMethodSuffix),
                    true
                );
            }

            //there is a return type, initialize it
            if (!string.Equals(interfaceMethod.ReturnType.WithoutTrivia().ToString(), "void"))
            {
                //create the concrete return type
                concreteReturnType = CreateConcreteSafeHandleType
                (
                    interfaceMethod,
                    interfaceMethod.ReturnType,
                    methodAttributes,
                    safeHandles,
                    true,
                    false
                )
                .WithoutTrivia();

                //(byte) ref return type
                if(concreteReturnType is RefTypeSyntax refTypeSyntax
                    && string.Equals(refTypeSyntax.Type.ToString(), "byte"))
                {
                    //"initialize" by ref byte return type
                    //using an empty span
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
                                                SyntaxFactory.RefExpression
                                                (
                                                    SyntaxFactory.InvocationExpression
                                                    (
                                                        SyntaxFactory.MemberAccessExpression
                                                        (
                                                            SyntaxKind.SimpleMemberAccessExpression,
                                                            SyntaxFactory.IdentifierName("MemoryMarshal"),
                                                            SyntaxFactory.IdentifierName("GetReference")
                                                        ),
                                                        SyntaxFactory.ArgumentList
                                                        (
                                                            SyntaxFactory.SeparatedList<ArgumentSyntax>
                                                            (
                                                                new ArgumentSyntax[]
                                                                {
                                                                    SyntaxFactory.Argument
                                                                    (
                                                                        SyntaxFactory.MemberAccessExpression
                                                                        (
                                                                            SyntaxKind.SimpleMemberAccessExpression,
                                                                            SyntaxFactory.GenericName
                                                                            (
                                                                                SyntaxFactory.Identifier("Span"),
                                                                                SyntaxFactory.TypeArgumentList
                                                                                (
                                                                                    SyntaxFactory.Token(SyntaxKind.LessThanToken),
                                                                                    SyntaxFactory.SeparatedList<TypeSyntax>
                                                                                    (
                                                                                        new TypeSyntax[]
                                                                                        {
                                                                                            SyntaxFactory.PredefinedType(SyntaxFactory.Token(SyntaxKind.ByteKeyword))
                                                                                        }
                                                                                    ),
                                                                                    SyntaxFactory.Token(SyntaxKind.GreaterThanToken)
                                                                                )
                                                                            ),
                                                                            SyntaxFactory.IdentifierName("Empty")
                                                                        )
                                                                    )
                                                                }
                                                            )
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
                else
                {
                    //initialize return type
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
                                            : SyntaxFactory.Identifier(_ReturnValueLocalName)
                                    )
                                    }
                                )
                            )
                        )
                    )
                    .NormalizeWhitespace();
                }
            }

            //first create locals for all generic type parameters
            //skipping out parameters, which are defined and assigned during invocation
            foreach (ParameterSyntax parameter in interfaceMethod.ParameterList.Parameters.Where
            (
                x => !x.Modifiers.Any(x => x.WithoutTrivia().ValueText.Equals("out"))
                    && ContainsGenericTypeParameter(x.Type, interfaceMethod.TypeParameterList, out _)
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

            //create locals for all out safe handles
            foreach (ParameterSyntax parameter in interfaceMethod.ParameterList.Parameters)
            {
                if (!parameter.Modifiers.Any(x => x.WithoutTrivia().ValueText.Equals("out")))
                {
                    continue;
                }

                string name = GetSafeHandleTypeNameWithoutGenericTypeList(parameter.Type);

                if (!safeHandles.Any(x => x.IsAbsract && x.Name.Equals(name)))
                {
                    continue;
                }

                blockSyntax = blockSyntax.AddStatements
                (
                    SyntaxFactory.LocalDeclarationStatement
                    (
                        SyntaxFactory.VariableDeclaration
                        (
                            CreateConcreteSafeHandleType
                            (
                                interfaceMethod,
                                parameter.Type,
                                parameter.AttributeLists,
                                safeHandles,
                                true,
                                false
                            )
                            .WithoutTrivia(),
                            SyntaxFactory.SeparatedList<VariableDeclaratorSyntax>
                            (
                                new VariableDeclaratorSyntax[]
                                {
                                    SyntaxFactory.VariableDeclarator
                                    (
                                        SyntaxFactory.Identifier(GenerateOutArgumentName(interfaceMethod, parameter, true, false))
                                    )
                                }
                            )
                        )
                    )
                )
                .NormalizeWhitespace();

            }

            //create windows condition
            if (needsWindowsOverride)
            {
                BlockSyntax windowsBlock = SyntaxFactory.Block
                (
                    concreteReturnType is null
                    ? SyntaxFactory.ExpressionStatement
                    (
                        winInvocation
                    )
                    : SyntaxFactory.ExpressionStatement
                    (
                        //this should never be a by ref!!
                        //TODO: byref return type
                        SyntaxFactory.AssignmentExpression
                        (
                            SyntaxKind.SimpleAssignmentExpression,
                            SyntaxFactory.IdentifierName(_ReturnValueLocalName),
                            winInvocation
                        )
                    )
                );

                //assign concrete windows native out parameters
                if (winInvocation.DescendantNodes().OfType<SingleVariableDesignationSyntax>().Any())
                {
                    //find all out paramters with (in)correct long types
                    foreach (ParameterSyntax parameter in interfaceMethod.ParameterList.Parameters.Where
                    (
                        x => x.Modifiers.Any(x => x.WithoutTrivia().ValueText.Equals("out"))
                            && NeedsWindowsOverride(x.AttributeLists)
                    ))
                    {
                        windowsBlock = windowsBlock.AddStatements
                        (
                            SyntaxFactory.ExpressionStatement
                            (
                                SyntaxFactory.AssignmentExpression
                                (
                                    SyntaxKind.SimpleAssignmentExpression,
                                    SyntaxFactory.IdentifierName(parameter.Identifier.WithoutTrivia()),
                                    SyntaxFactory.IdentifierName(GenerateOutArgumentName(interfaceMethod, parameter, false, true))
                                )
                            )
                        )
                        .NormalizeWhitespace();
                    }
                }

                blockSyntax = blockSyntax.AddStatements
                (
                    SyntaxFactory.IfStatement
                    (
                        SyntaxFactory.InvocationExpression
                        (
                            SyntaxFactory.MemberAccessExpression
                            (
                                SyntaxKind.SimpleMemberAccessExpression,
                                SyntaxFactory.IdentifierName("OperatingSystem"),
                                SyntaxFactory.IdentifierName("IsWindows")
                            )
                        ),
                        //windows
                        windowsBlock,
                        //not windows
                        SyntaxFactory.ElseClause
                        (
                            SyntaxFactory.Block
                            (
                                concreteReturnType is null
                                ? SyntaxFactory.ExpressionStatement
                                (
                                    invocation
                                )
                                : SyntaxFactory.ExpressionStatement
                                (
                                    SyntaxFactory.AssignmentExpression
                                    (
                                        SyntaxKind.SimpleAssignmentExpression,
                                        string.Equals(concreteReturnType.ToString(), _PtrTypeName)
                                            && !string.Equals(concreteReturnType.ToString(), interfaceMethod.ReturnType.WithoutTrivia().ToString())
                                            ? SyntaxFactory.IdentifierName(_PtrReturnValueLocalName)
                                            : SyntaxFactory.IdentifierName(_ReturnValueLocalName),
                                        interfaceMethod.ReturnType is RefTypeSyntax
                                            ? SyntaxFactory.RefExpression
                                            (
                                                invocation
                                            )
                                            : invocation
                                    )
                                )
                            )
                        )
                    )
                )
                .NormalizeWhitespace();
            }
            //no return type
            else if (concreteReturnType is null)
            {
                blockSyntax = blockSyntax.AddStatements
                (
                    SyntaxFactory.ExpressionStatement
                    (
                        invocation
                    )
                );
            }
            //assign return type
            else
            {
                blockSyntax = blockSyntax.AddStatements
                (
                    SyntaxFactory.ExpressionStatement
                    (
                        SyntaxFactory.AssignmentExpression
                        (
                            SyntaxKind.SimpleAssignmentExpression,
                            string.Equals(concreteReturnType.ToString(), _PtrTypeName)
                                && !string.Equals(concreteReturnType.ToString(), interfaceMethod.ReturnType.WithoutTrivia().ToString())
                                ? SyntaxFactory.IdentifierName(_PtrReturnValueLocalName)
                                : SyntaxFactory.IdentifierName(_ReturnValueLocalName),
                            interfaceMethod.ReturnType is RefTypeSyntax
                                ? SyntaxFactory.RefExpression
                                (
                                    invocation
                                )
                                : invocation
                        )
                    )
                )
                .NormalizeWhitespace();
            }

            LocalDeclarationStatementSyntax localDeclarationStatementSyntax;

            //check if a return type should be constructed
            if (AssignConcreteTypeFromPointer
            (
                interfaceMethod,
                interfaceMethod.ReturnType,
                SyntaxFactory.Identifier(_ReturnValueLocalName),
                SyntaxFactory.Identifier(_PtrReturnValueLocalName),
                methodAttributes,
                safeHandles,
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
                        && ContainsGenericTypeParameter(x.Type, interfaceMethod.TypeParameterList, out _)
            ))
            {
                if (AssignConcreteTypeFromPointer
                (
                    interfaceMethod,
                    parameter.Type,
                    SyntaxFactory.Identifier(GenerateOutArgumentName(interfaceMethod, parameter, false, false)),
                    SyntaxFactory.Identifier(GenerateOutArgumentName(interfaceMethod, parameter, true, false)),
                    methodAttributes,
                    safeHandles,
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

            //check return type
            if (!methodAttributes.Any(x => x.Attributes.Any(y => string.Equals(y.Name.ToString(), _DontVerifyTypeName))))
            {
                if (concreteReturnType is not null
                    && HasSupportedVerificationType
                    (
                        interfaceMethod,
                        interfaceMethod.ReturnType,
                        SyntaxFactory.IdentifierName(_ReturnValueLocalName),
                        safeHandles,
                        out verificationExpression
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
                }
            }

            //check safe handle and all IntPtr out parameter
            foreach (ParameterSyntax parameter in interfaceMethod.ParameterList.Parameters.Where
            (
                x => x.Modifiers.Any(y => y.WithoutTrivia().ValueText.Equals("out"))
                    && !x.AttributeLists.Any(x => x.Attributes.Any(y => string.Equals(y.Name.ToString(), _DontVerifyTypeName)))
                    && (IsSafeHandle(x.Type, safeHandles)
                        || ContainsGenericTypeParameter(x.Type, interfaceMethod.TypeParameterList, out _))
            ))
            {
                if (!HasSupportedVerificationType
                (
                    interfaceMethod,
                    parameter.Type,
                    SyntaxFactory.IdentifierName(GenerateOutArgumentName(interfaceMethod, parameter, false, false)),
                    safeHandles,
                    out verificationExpression
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
            }

            //find all safe handle out paramters
            foreach (ParameterSyntax parameter in interfaceMethod.ParameterList.Parameters.Where
            (
                x => x.Modifiers.Any(x => x.WithoutTrivia().ValueText.Equals("out"))
                    && safeHandles.Any(y => y.IsAbsract && y.Name.Equals(GetSafeHandleTypeNameWithoutGenericTypeList(x.Type)))
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
                            SyntaxFactory.IdentifierName(GenerateOutArgumentName(interfaceMethod, parameter, false, false))
                        )
                    )
                )
                .NormalizeWhitespace();
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
            ICollection<SafeHandleModel> safeHandles,
            string nativeMethodName,
            bool isWindowsCall
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
                                ? GenerateOutArgument(interfaceMethod, x, safeHandles, isWindowsCall)
                                : GenerateArgument(interfaceMethod, x, isWindowsCall)
                        )
                    )
                )
            );

        private static ArgumentSyntax GenerateOutArgument
        (
            MethodDeclarationSyntax interfaceMethod,
            ParameterSyntax parameterSyntax,
            ICollection<SafeHandleModel> safeHandles,
            bool isWindowsCall
        )
        {
            string name = GetSafeHandleTypeNameWithoutGenericTypeList(parameterSyntax.Type);

            //parameter contains an abstract safe handle type
            //declare a local
            if (safeHandles.Any(x => x.IsAbsract && x.Name.Equals(name)))
            {
                return SyntaxFactory.Argument
                (
                    null,
                    parameterSyntax.Modifiers.First(), //should always be single
                    SyntaxFactory.IdentifierName(GenerateOutArgumentName(interfaceMethod, parameterSyntax, true, false))
                );
            }
            else if (isWindowsCall
                && NeedsWindowsOverride(parameterSyntax.AttributeLists))
            {
                return SyntaxFactory.Argument
                (
                    null,
                    parameterSyntax.Modifiers.First(), //should always be single
                    SyntaxFactory.DeclarationExpression
                    (
                        CreateWindowsNativeLongType
                        (
                            interfaceMethod,
                            parameterSyntax.Type,
                            parameterSyntax.AttributeLists,
                            false
                        ),
                        SyntaxFactory.SingleVariableDesignation
                        (
                            SyntaxFactory.Identifier(GenerateOutArgumentName(interfaceMethod, parameterSyntax, true, true))
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
            MethodDeclarationSyntax method,
            ParameterSyntax parameterSyntax,
            bool isNativeCall,
            bool isWindowsCall
        )
        {
            string name = GetSafeHandleTypeNameWithoutGenericTypeList(parameterSyntax.Type);

            //if the parameter is a SafeStackhandle
            //or a generic type parameter
            //return pointer out name
            if (isNativeCall
                && ContainsGenericTypeParameter(parameterSyntax.Type, method.TypeParameterList, out _))
            {
                return string.Concat
                (
                    _OutParameterNamePrefix,
                    _PtrNamePrefix,
                    parameterSyntax.Identifier.WithoutTrivia()
                );
            }
            else if (isWindowsCall)
            {
                return string.Concat
                (
                    _WindowsArgumentPrefix,
                    _OutParameterNamePrefix,
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

        private static ArgumentSyntax GenerateArgument
        (
            MethodDeclarationSyntax interfaceMethod,
            ParameterSyntax parameterSyntax,
            bool isWindowsCall
        )
        {
            //if it's generic, use a ptr
            if (ContainsGenericTypeParameter(parameterSyntax.Type, interfaceMethod.TypeParameterList, out _))
            {
                return SyntaxFactory.Argument
                (
                    null,
                    parameterSyntax.Modifiers.FirstOrDefault(),
                    SyntaxFactory.IdentifierName
                    (
                        string.Concat(_PtrNamePrefix, parameterSyntax.Identifier.WithoutTrivia())
                    )
                );
            }

            //if it's a NativeLong, it needs to be down casted
            if (isWindowsCall
                && NeedsWindowsOverride(parameterSyntax.AttributeLists))
            {
                return SyntaxFactory.Argument
                (
                    null,
                    parameterSyntax.Modifiers.FirstOrDefault(),
                    SyntaxFactory.CastExpression
                    (
                        CreateWindowsNativeLongType
                        (
                            interfaceMethod,
                            parameterSyntax.Type,
                            parameterSyntax.AttributeLists,
                            false
                        ),
                        SyntaxFactory.IdentifierName(parameterSyntax.Identifier.WithoutTrivia())
                    )
                );
            }

            //else pass the argument as is
            return SyntaxFactory.Argument
            (
                null,
                parameterSyntax.Modifiers.FirstOrDefault(),
                SyntaxFactory.IdentifierName(parameterSyntax.Identifier.WithoutTrivia())
            );
        }

        private static bool AssignConcreteTypeFromPointer
        (
            MethodDeclarationSyntax method,
            TypeSyntax typeSyntax,
            SyntaxToken localName,
            SyntaxToken ptrLocalName,
            SyntaxList<AttributeListSyntax> symbolAttributes,
            ICollection<SafeHandleModel> safeHandles,
            MethodDeclarationSyntax interfaceMethod,
            out LocalDeclarationStatementSyntax localDeclaration
        )
        {
            //a new (concrete) safe handle should be created
            if (ContainsGenericTypeParameter
            (
                typeSyntax,
                method.TypeParameterList,
                out bool isTypeParameter
            ))
            {
                //it's a generic type parameter, call the factory
                if (isTypeParameter)
                {
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
                        method,
                        typeSyntax,
                        symbolAttributes,
                        safeHandles,
                        false,
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
