# NetSlurper

Python toolkit for easy extraction of signature patterns from certain not so obvious parts of .NET assemblies

So far it only contains one tool: dotnet_typesig2yara.py

This tool creates a Yara rule containing a method's type signature. 
It needs the fully qualified name for a method in a .NET file as well as the file itself.

Prerequisite: Put ildasm.exe in PATH variable
Usage: dotnet_typesig2yara.py "foo.bar::Baz" sample.exe
