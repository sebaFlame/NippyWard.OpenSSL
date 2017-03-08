//download binaries
//https://indy.fulgan.com/SSL/ ( openssl-1.0.2k-i386-win32.zip & openssl-1.0.2k-x64_86-win64.zip  )
//copy i386/x64_x86 libeay32.dll & i386/x64_x86 ssleay32.dll into x86/x64 folder
//copy libeay32.dll in each folder to libcrypto.dll
//change version to correct one in project.json
dotnet build
dotnet pack
//with nuget >= 3.3
nuget add OpenSSL.version.nupkg -expand -source $HOME/.nuget/packages