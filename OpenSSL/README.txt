//download binaries
//https://www.npcglib.org/~stathis/blog/precompiled-openssl/ ( v1.0.2k (stable) )
//copy bin[64]/*MD.dll into x86/x64 folder
//change version to correct one in project.json
dotnet build
dotnet pack
//with nuget >= 3.3
nuget add OpenSSL.version.nupkg -expand -source $HOME/.nuget/packages