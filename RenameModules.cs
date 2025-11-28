using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

    public static class RenameModules
    {
        private static readonly Random _random = new Random();
        public static void Execute()
        {
            bool TypeMessage;
            try
            {
                var mainModule = Process.GetCurrentProcess().MainModule;
                if (mainModule != null)
                {
                    string originalName = mainModule.ModuleName;
                    string newName = GenerateRandomString(7) + ".dll";

                    if (RenameModule(originalName, newName))
                    {
                        ConsoleHalper($"{originalName} -> {newName}", TypeMessage = true);
                    }
                }

                string[] suspiciousModules =
                {
                    "clr.dll",
                    "coreclr.dll",
                    "clrjit.dll",
                    "mscoree.dll",
                    "hostfxr.dll",
                    "hostpolicy.dll",
                    "System.Private.CoreLib.dll"
                };

                foreach (var moduleName in suspiciousModules)
                {
                    string newDllName = GenerateRandomString(7) + ".sys";

                    if (RenameModule(moduleName, newDllName))
                    {
                        ConsoleHalper($"{moduleName} -> {newDllName}", TypeMessage = true);
                    }
                }
            }
            catch (Exception ex)
            {
                ConsoleHalper($"{ex.Message}", TypeMessage = false);
            }
        }

        private static void ConsoleHalper(string line, bool IsErrorOrSuccess)
        {
            if (IsErrorOrSuccess) { Console.ForegroundColor = ConsoleColor.Green; Console.WriteLine(line); }
            else { Console.ForegroundColor = ConsoleColor.Red; Console.WriteLine(line); }
            Console.ResetColor();
        }

        private static string GenerateRandomString(int length)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            char[] stringChars = new char[length];
            lock (_random)
            {
                for (int i = 0; i < length; i++)
                {
                    stringChars[i] = chars[_random.Next(chars.Length)];
                }
            }
            return new string(stringChars);
        }

        private static bool RenameModule(string originalName, string newName)
        {
            IntPtr pPeb = GetPebAddress();
            if (pPeb == IntPtr.Zero) return false;

            IntPtr pLdr = Marshal.ReadIntPtr(pPeb, (int)Marshal.OffsetOf<PEB>("Ldr"));

            int inLoadOrderLinksOffset = (int)Marshal.OffsetOf<LDR_DATA_TABLE_ENTRY>("InLoadOrderLinks");
            int inMemoryOrderLinksOffset = (int)Marshal.OffsetOf<LDR_DATA_TABLE_ENTRY>("InMemoryOrderLinks");
            int inInitOrderLinksOffset = (int)Marshal.OffsetOf<LDR_DATA_TABLE_ENTRY>("InInitializationOrderLinks");

            IntPtr ldrInLoadOrderListHead = pLdr + (int)Marshal.OffsetOf<PEB_LDR_DATA>("InLoadOrderModuleList");
            IntPtr ldrInMemoryOrderListHead = pLdr + (int)Marshal.OffsetOf<PEB_LDR_DATA>("InMemoryOrderModuleList");
            IntPtr ldrInInitOrderListHead = pLdr + (int)Marshal.OffsetOf<PEB_LDR_DATA>("InInitializationOrderModuleList");

            bool f1 = RenameInLdrList(ldrInLoadOrderListHead, inLoadOrderLinksOffset, originalName, newName);
            bool f2 = RenameInLdrList(ldrInMemoryOrderListHead, inMemoryOrderLinksOffset, originalName, newName);
            bool f3 = RenameInLdrList(ldrInInitOrderListHead, inInitOrderLinksOffset, originalName, newName);

            return f1 || f2 || f3;
        }

        private static bool RenameInLdrList(IntPtr listHead, int linkOffset, string originalName, string newName)
        {
            IntPtr currentLink = Marshal.ReadIntPtr(listHead);
            bool found = false;

            while (currentLink != listHead && currentLink != IntPtr.Zero)
            {
                IntPtr pLdrEntry = currentLink - linkOffset;
                var entry = Marshal.PtrToStructure<LDR_DATA_TABLE_ENTRY>(pLdrEntry);

                string currentModuleName = Marshal.PtrToStringUni(entry.BaseDllName.Buffer, entry.BaseDllName.Length / 2);

                if (!string.IsNullOrEmpty(currentModuleName) && currentModuleName.Equals(originalName, StringComparison.OrdinalIgnoreCase))
                {
                    string fakeFullPath = $"C:\\Windows\\System32\\{newName}";
                    OverwriteUnicodeString(pLdrEntry, "BaseDllName", newName);
                    OverwriteUnicodeString(pLdrEntry, "FullDllName", fakeFullPath);
                    found = true;
                }
                currentLink = Marshal.ReadIntPtr(currentLink);
            }
            return found;
        }

        private static void OverwriteUnicodeString(IntPtr pLdrEntry, string fieldName, string newString)
        {
            int fieldOffset = (int)Marshal.OffsetOf<LDR_DATA_TABLE_ENTRY>(fieldName);
            IntPtr pUnicodeString = pLdrEntry + fieldOffset;

            var originalString = Marshal.PtrToStructure<UNICODE_STRING>(pUnicodeString);
            if (originalString.Buffer == IntPtr.Zero) return;

            byte[] newBytes = Encoding.Unicode.GetBytes(newString);
            int bytesToWrite = Math.Min(newBytes.Length, originalString.MaximumLength - 2);

            if (WriteProtectedMemory(originalString.Buffer, newBytes, bytesToWrite))
            {
                int remaining = originalString.MaximumLength - bytesToWrite;
                if (remaining > 0)
                    WriteProtectedMemory(originalString.Buffer + bytesToWrite, new byte[remaining], remaining);

                IntPtr pLength = pUnicodeString + (int)Marshal.OffsetOf<UNICODE_STRING>("Length");
                WriteProtectedMemory(pLength, BitConverter.GetBytes((ushort)bytesToWrite), 2);
            }
        }

        private static bool WriteProtectedMemory(IntPtr address, byte[] data, int length)
        {
            if (VirtualProtect(address, (UIntPtr)length, 0x40, out uint oldProtect))
            {
                Marshal.Copy(data, 0, address, length);
                VirtualProtect(address, (UIntPtr)length, oldProtect, out _);
                return true;
            }
            return false;
        }

        private static IntPtr GetPebAddress()
        {
            byte[] code = IntPtr.Size == 8
                ? new byte[] { 0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, 0xC3 }
                : new byte[] { 0x64, 0xA1, 0x30, 0x00, 0x00, 0x00, 0xC3 };

            IntPtr pCode = VirtualAlloc(IntPtr.Zero, (uint)code.Length, 0x3000, 0x40);
            if (pCode == IntPtr.Zero) return IntPtr.Zero;

            try
            {
                var del = (GetPebDelegate)Marshal.GetDelegateForFunctionPointer(pCode, typeof(GetPebDelegate));
                Marshal.Copy(code, 0, pCode, code.Length);
                return del();
            }
            finally { VirtualFree(pCode, 0, 0x8000); }
        }

        private delegate IntPtr GetPebDelegate();

        [DllImport("kernel32.dll")] private static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
        [DllImport("kernel32.dll")] private static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32.dll")] private static extern bool VirtualFree(IntPtr lpAddress, uint dwSize, uint dwFreeType);

        [StructLayout(LayoutKind.Sequential)] private struct UNICODE_STRING { public ushort Length; public ushort MaximumLength; public IntPtr Buffer; }
        [StructLayout(LayoutKind.Sequential)] private struct PEB { [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)] public byte[] Reserved1; public byte BeingDebugged; [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)] public byte[] Reserved2; [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)] public IntPtr[] Reserved3; public IntPtr Ldr; }
        [StructLayout(LayoutKind.Sequential)] private struct PEB_LDR_DATA { public uint Length; public byte Initialized; public IntPtr SsHandle; public LIST_ENTRY InLoadOrderModuleList; public LIST_ENTRY InMemoryOrderModuleList; public LIST_ENTRY InInitializationOrderModuleList; }
        [StructLayout(LayoutKind.Sequential)] private struct LIST_ENTRY { public IntPtr Flink; public IntPtr Blink; }
        [StructLayout(LayoutKind.Sequential)] private struct LDR_DATA_TABLE_ENTRY { public LIST_ENTRY InLoadOrderLinks; public LIST_ENTRY InMemoryOrderLinks; public LIST_ENTRY InInitializationOrderLinks; public IntPtr DllBase; public IntPtr EntryPoint; public uint SizeOfImage; public UNICODE_STRING FullDllName; public UNICODE_STRING BaseDllName; }
    }