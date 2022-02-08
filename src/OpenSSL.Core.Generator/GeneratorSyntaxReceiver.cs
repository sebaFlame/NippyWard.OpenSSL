using System;
using System.Collections.Generic;
using System.Linq;

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace OpenSSL.Core.Generator
{
    internal class GeneratorSyntaxReceiver : ISyntaxReceiver
    {
        private const string _SslWrapperName = "ILibSSLWrapper";
        private const string _CryptoWrapperName = "ILibCryptoWrapper";
        private const string _StackWrapperName = "IStackWrapper";
        private const string _SafeHandleFactoryName = "ISafeHandleFactory";
        private const string _SafeHandlesNamespaceName = "OpenSSL.Core.Interop.SafeHandles";

        private IList<ClassDeclarationSyntax> _safeHandleCandidates;

        internal InterfaceDeclarationSyntax SslWrapper { get; private set; }
        internal InterfaceDeclarationSyntax CryptoWrapper { get; private set; }
        internal InterfaceDeclarationSyntax StackWrapper { get; private set; }
        internal InterfaceDeclarationSyntax FactoryWrapper { get; private set; }
        internal ICollection<ClassDeclarationSyntax> SafeHandleCandidates => this._safeHandleCandidates;

        public GeneratorSyntaxReceiver()
        {
            this._safeHandleCandidates = new List<ClassDeclarationSyntax>();
        }

        public void OnVisitSyntaxNode(SyntaxNode syntaxNode)
        {
            NamespaceDeclarationSyntax namespaceDeclaration;

            if (syntaxNode is InterfaceDeclarationSyntax interfaceDeclaration)
            {
                if(string.Equals(_SslWrapperName, interfaceDeclaration.Identifier.Text))
                {
                    this.SslWrapper = interfaceDeclaration;
                }
                else if (string.Equals(_CryptoWrapperName, interfaceDeclaration.Identifier.Text))
                {
                    this.CryptoWrapper = interfaceDeclaration;
                }
                else if (string.Equals(_StackWrapperName, interfaceDeclaration.Identifier.Text))
                {
                    this.StackWrapper = interfaceDeclaration;
                }
                else if (string.Equals(_SafeHandleFactoryName, interfaceDeclaration.Identifier.Text))
                {
                    this.FactoryWrapper = interfaceDeclaration;
                }
            }

            //create a list of BaseRefernce or BaseValue candidates
            if(syntaxNode is ClassDeclarationSyntax classDeclaration
                && (namespaceDeclaration = WrapperGenerator.FindParentNamespace(classDeclaration)) is not null
                && namespaceDeclaration.Name.ToString().Contains(_SafeHandlesNamespaceName))
            {
                this._safeHandleCandidates.Add(classDeclaration);
            }
        }
    }
}
