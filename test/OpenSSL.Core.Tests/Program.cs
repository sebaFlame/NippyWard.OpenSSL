using System;
using System.Reflection;

namespace OpenSSL.Core.Tests
{
    public class Program
    {
        public static void Main(string[] args)
        {
            //new AutoRun(typeof(Program).GetTypeInfo().Assembly)
            //    .Execute(args, new ExtendedTextWrapper(Console.Out), Console.In);

            string path = typeof(Program).GetTypeInfo().Assembly.Location;
            Xunit.Runner.DotNet.Program.Main(new string[] { path });
            Console.WriteLine("Press any key to exit...");
            Console.ReadKey();
        }
    }
}