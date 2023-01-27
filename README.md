

## First things first

Manage to build it.
In the demo I used :

 - Configuration: Release|AnyCPU
 - Target framework: net7.0 
 - Deployment mode: Framwork-dependent 
 - target-runtime: win-x64
 - ✓ Produce single file

I added an obfuscator (obfuscar) with the following settings:

     <Var name="RegenerateDebugInfo" value="true" />
      <Var name="MarkedOnly" value="false" />
      <Var name="RenameProperties" value="true" />
      <Var name="RenameEvents" value="true" />
      <Var name="RenameFields" value="true" />
      <Var name="KeepPublicApi" value="true" />
      <Var name="HidePrivateApi" value="true" />
      <Var name="ReuseNames" value="true" />
      <Var name="HideStrings" value="true" />
      <Var name="OptimizeMethods" value="true" />
      <Var name="SuppressIldasm" value="true" />
      <Var name="AnalyzeXaml" value="true" />
      <Var name="UseUnicodeNames" value="true" />
      <Var name="UseKoreanNames" value="true" />
     <Module file="$(InPath)\blah.dll">
    <SkipType name="*AnonymousType*" skipProperties="false" skipMethods="false" skipFields="false" skipEvents="false" skipStringHiding="false" />
    </Module>

## Usage

 -  -url: url where your shellcode is hosted
 -  -pname: the process you want to inject into
 -  -selfinject: if you don't use -pname, it will inject the shellcode on the running process
 -  -key: the b64 key to decrypt your shellcode if you AES encrypted it,
 
## Credits
The API unhooking (ntdll.dll, kernel32.dll, advapi32.dll, and kernelbase.dll),EAT hooks, IAT hooks, and JMP/Hot-patch/Inline hooks, AMSI and ETW patches are totally stolen from https://github.com/GetRektBoy724/SharpUnhooker 

## Demo
![enter image description here](https://github.com/soufianetahiri/RemoteShellCodeInjection/blob/master/demo_opti.gif?raw=true)

## Disclamer
 For educational purposes only...😐
