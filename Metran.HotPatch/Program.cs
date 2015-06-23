using System.Linq;
using System.Text;

namespace Metran.HotPatch
{
    using Metran.LowLevelAccess;
    using Metran.LowLevelAccess.UnmanagedMemory;
    using System;
    using System.Collections.Generic;
    using System.ComponentModel;
    using System.Diagnostics;
    using System.Globalization;
    using System.IO;
    using System.Runtime.InteropServices;
    using System.Windows.Forms;
    using System.Xml.Linq;

    internal static class Program
    {
        /// <summary>
        /// The suffix of the file name to get the input data from
        /// </summary>
        private const string PatchFileNameSuffix = "HotPatch.xml";

        /// <summary>
        /// The name of the 'version' attribute
        /// </summary>
        private const string VersionNameAttribute = "version";

        /// <summary>
        /// The name of the 'targetName' attribute
        /// </summary>
        private const string TargetNameAttribute = "targetName";

        /// <summary>
        /// The name of the 'libraryName' attribute
        /// </summary>
        private const string LibraryNameAttribute = "libraryName";

        /// <summary>
        /// The name of the 'Patch' tag
        /// </summary>
        private const string PatchTag = "Patch";

        /// <summary>
        /// The name of the 'PatchLibrary' tag
        /// </summary>
        private const string PatchLibraryTag = "PatchLibrary";

        /// <summary>
        /// The name of the 'offset' attribute
        /// </summary>
        private const string OffsetAttribute = "offset";

        /// <summary>
        /// The name of the 'data' attribute
        /// </summary>
        private const string DataAttribute = "data";

        /// <summary>
        /// The data bytes separator
        /// </summary>
        private const char DataBytesSeparator = ' ';

        /// <summary>
        /// The current version of the utility
        /// </summary>
        private const float CurrentVersion = 3;

        /// <summary>
        /// The libraries loaded into the main executable
        /// </summary>
        private static readonly Dictionary<string, IntPtr> LoadedLibraries = new Dictionary<string, IntPtr>();

        [STAThread]
        private static void Main()
        {
            var patchFileName =
                Path.GetFileNameWithoutExtension(Process.GetCurrentProcess().ProcessName) +
                PatchFileNameSuffix;

            try
            {
                var patchDocument = XElement.Load(patchFileName);

                var versionAttr = patchDocument.Attribute(VersionNameAttribute);
                if (versionAttr == null)
                {
                    throw new InvalidOperationException("The version attribute is not found");
                }

                if (float.Parse(versionAttr.Value, new CultureInfo("en-US")) > CurrentVersion)
                {
                    throw new NotSupportedException("This version of patch data is not supported");
                }

                var targetNameAttr = patchDocument.Attribute(TargetNameAttribute);
                if (targetNameAttr == null)
                {
                    throw new InvalidOperationException("The target name attribute is not found");
                }

                var startupInfo = new StartupInfo();
                startupInfo.cb = (uint)Marshal.SizeOf(typeof(StartupInfo));

                ProcessInformation processInformation;
                var result = Kernel32.CreateProcess(
                    null,
                    targetNameAttr.Value,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    false,
                    ProcessCreationFlags.Suspended,
                    IntPtr.Zero,
                    null,
                    ref startupInfo,
                    out processInformation);
                ValidateResult(result);

                PatchExecutable(processInformation, patchDocument);
                PatchLibraries(processInformation, patchDocument);

                Kernel32.ResumeThread(processInformation.hThread);
            }
            catch (Exception e)
            {
                MessageBox.Show(
                    e.Message,
                    string.Format("Error"),
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
            }
        }

        /// <summary>
        /// Populates the list of loaded modules within the specified process
        /// </summary>
        /// <param name="hProcess">The handle of the process to populate the list of modules</param>
        private static void EnumModules(IntPtr hProcess)
        {
            using (var alloc = new CoTaskMemoryAllocator(0x10000))
            {
                int needed;
                var result = Kernel32.EnumProcessModulesExPsapi(
                    hProcess,
                    alloc,
                    alloc.BufferLength,
                    out needed,
                    ListModulesFlag.LIST_MODULES_ALL);
                ValidateResult(result);

                for (var i = 0; i < needed / IntPtr.Size; i++)
                {
                    var hModule = Marshal.ReadIntPtr(alloc.BufferAddress, i * IntPtr.Size);

                    var baseName = new StringBuilder(260);
                    result = Kernel32.GetModuleFileNameExWPsapi(hProcess, hModule, baseName, baseName.Capacity);
                    ValidateResult(result);

                    LoadedLibraries.Add(Path.GetFileName(baseName.ToString()).ToLower(), hModule);
                }
            }
        }

        /// <summary>
        /// Patches the main executable
        /// </summary>
        /// <param name="processInformation">The <see cref="ProcessInformation"/> corresponding to the main executable</param>
        /// <param name="patchDocument">The <see cref="XElement"/> containing the data to use</param>
        private static void PatchExecutable(ProcessInformation processInformation, XElement patchDocument)
        {
            foreach (var patch in patchDocument.Elements(PatchTag))
            {
                var offsetAttr = patch.Attribute(OffsetAttribute);
                if (offsetAttr == null)
                {
                    throw new InvalidOperationException("The offset attribute is not found");
                }

                var dataAttr = patch.Attribute(DataAttribute);
                if (dataAttr == null)
                {
                    throw new InvalidOperationException("The data attribute is not found");
                }

                var offset = ParseAddress(offsetAttr.Value);
                var baseAddress = GetExecutableBaseAddress(processInformation);
                if (baseAddress == IntPtr.Zero)
                {
                    throw new InvalidOperationException("The base address of the main executable is not found");
                }
                var address = new IntPtr(baseAddress.ToInt64() + offset.ToInt64());

                var data = ParseData(dataAttr.Value);

                MemoryProtection oldProtect;
                var result = Kernel32.VirtualProtectEx(
                    processInformation.hProcess,
                    address,
                    (uint)data.Length,
                    MemoryProtection.ExcecuteReadWrite,
                    out oldProtect);
                ValidateResult(result);

                using (var alloc = new CoTaskMemoryAllocator(data.Length))
                {
                    alloc.Write(data);

                    uint mumberOfBytesWritten;
                    result = Kernel32.WriteProcessMemory(
                        processInformation.hProcess,
                        address,
                        alloc.BufferAddress,
                        (uint)alloc.BufferLength,
                        out mumberOfBytesWritten);
                    ValidateResult(result);
                }

                result = Kernel32.VirtualProtectEx(
                    processInformation.hProcess,
                    address,
                    (uint)data.Length,
                    oldProtect,
                    out oldProtect);
                ValidateResult(result);
            }
        }

        /// <summary>
        /// Loads libraries into the main executable and patches them as needed
        /// </summary>
        /// <param name="processInformation">The <see cref="ProcessInformation"/> corresponding to the main executable</param>
        /// <param name="patchDocument">The <see cref="XElement"/> containing the data to use</param>
        private static void PatchLibraries(ProcessInformation processInformation, XElement patchDocument)
        {
            foreach (var patchLibrary in patchDocument.Elements(PatchLibraryTag))
            {
                var libraryNameAttr = patchLibrary.Attribute(LibraryNameAttribute);
                if (libraryNameAttr == null)
                {
                    throw new InvalidOperationException("The library name attribute is not found");
                }

                var offsetAttr = patchLibrary.Attribute(OffsetAttribute);
                if (offsetAttr == null)
                {
                    throw new InvalidOperationException("The offset attribute is not found");
                }

                var dataAttr = patchLibrary.Attribute(DataAttribute);
                if (dataAttr == null)
                {
                    throw new InvalidOperationException("The data attribute is not found");
                }

                var offset = ParseAddress(offsetAttr.Value);
                var data = ParseData(dataAttr.Value);

                var libraryHandle = GetLibraryAddress(libraryNameAttr.Value, (int)processInformation.dwProcessId);

                MemoryProtection oldProtect;
                var result = Kernel32.VirtualProtectEx(
                    processInformation.hProcess,
                    libraryHandle + (int)offset,
                    (uint)data.Length,
                    MemoryProtection.ExcecuteReadWrite,
                    out oldProtect);
                ValidateResult(result);

                using (var alloc = new CoTaskMemoryAllocator(data.Length))
                {
                    alloc.Write(data);

                    uint mumberOfBytesWritten;
                    result = Kernel32.WriteProcessMemory(
                        processInformation.hProcess,
                        libraryHandle + (int)offset,
                        alloc.BufferAddress,
                        (uint)alloc.BufferLength,
                        out mumberOfBytesWritten);
                    ValidateResult(result);
                }

                result = Kernel32.VirtualProtectEx(
                    processInformation.hProcess,
                    libraryHandle + (int)offset,
                    (uint)data.Length,
                    oldProtect,
                    out oldProtect);
                ValidateResult(result);
            }
        }

        /// <summary>
        /// Returns a library handle corresponding to the specified library name and injecting it into the specified process as needed
        /// </summary>
        /// <param name="libraryName">The name of the library whose handle to return</param>
        /// <param name="processId">The process ID which to inject the library into</param>
        /// <returns>A library handle corresponding to the specified library name</returns>
        private static IntPtr GetLibraryAddress(string libraryName, int processId)
        {
            IntPtr libraryHandle;

            var libraryNameTrimmed = Path.GetFileNameWithoutExtension(libraryName).ToLower();

            if (LoadedLibraries.ContainsKey(libraryNameTrimmed))
            {
                libraryHandle = LoadedLibraries[libraryNameTrimmed];
            }
            else
            {
                using (var dllInject = new DllInjection(libraryName, processId))
                {
                    dllInject.Inject();

                    libraryHandle = dllInject.InjectedLibraryHandle;

                    LoadedLibraries.Add(libraryNameTrimmed, libraryHandle);
                }
            }

            return libraryHandle;
        }

        /// <summary>
        /// Returns the base address of the main executable of the specified process
        /// </summary>
        /// <param name="processInformation">The process for which to return the base address</param>
        /// <returns>The base address of the main executable of the specified process</returns>
        private static IntPtr GetExecutableBaseAddress(ProcessInformation processInformation)
        {
            var baseAddress = IntPtr.Zero;

            var scanAddress = IntPtr.Zero;
            MemoryBasicInformation mbi;
            var size = Marshal.SizeOf(typeof(MemoryBasicInformation));

            Kernel32.VirtualQueryEx(processInformation.hProcess, scanAddress, out mbi, (uint)size);
            if (Marshal.GetLastWin32Error() == 24)
            {
                MemoryBasicInformation64 mbi64;
                size = Marshal.SizeOf(typeof(MemoryBasicInformation64));

                while (Kernel32.VirtualQueryEx64(processInformation.hProcess, scanAddress, out mbi64, (uint)size) == size)
                {
                    if (mbi64.Type == MemoryBasicInformationType.MemImage)
                    {
                        baseAddress = mbi64.AllocationBase;
                        break;
                    }

                    scanAddress = new IntPtr(scanAddress.ToInt64() + mbi64.RegionSize);
                }
            }
            else
            {
                while (Kernel32.VirtualQueryEx(processInformation.hProcess, scanAddress, out mbi, (uint)size) == size)
                {
                    if (mbi.Type == MemoryBasicInformationType.MemImage)
                    {
                        baseAddress = mbi.AllocationBase;
                        break;
                    }

                    scanAddress += mbi.RegionSize;
                }
            }

            return baseAddress;
        }

        /// <summary>
        /// Returns an <see cref="IntPtr"/> corresponding to the specified <see cref="string"/>
        /// </summary>
        /// <param name="addressValue">The <see cref="string"/> for which to return an <see cref="IntPtr"/></param>
        /// <returns>An <see cref="IntPtr"/> corresponding to the specified <see cref="string"/></returns>
        private static IntPtr ParseAddress(string addressValue)
        {
            try
            {
                var address = int.Parse(
                        addressValue,
                        NumberStyles.HexNumber,
                        new CultureInfo("en-US"));

                return new IntPtr(address);
            }
            catch (OverflowException)
            {
                var address = long.Parse(
                        addressValue,
                        NumberStyles.HexNumber,
                        new CultureInfo("en-US"));

                return new IntPtr(address);
            }
        }

        /// <summary>
        /// Returns an array of <see cref="byte"/> corresponding to the specified <see cref="string"/>
        /// </summary>
        /// <param name="dataValue">The <see cref="string"/> for which to return an array of <see cref="byte"/></param>
        /// <returns>An array of <see cref="byte"/> corresponding to the specified <see cref="string"/></returns>
        private static byte[] ParseData(string dataValue)
        {
            var bytes = new List<byte>();

            if (!string.IsNullOrEmpty(dataValue))
            {
                var parts = dataValue.Split(DataBytesSeparator);

                bytes.AddRange(parts.Select(p => byte.Parse(p, NumberStyles.HexNumber, new CultureInfo("en-US"))));
            }

            return bytes.ToArray();
        }

        /// <summary>
        /// Validates the specified flag and throws a <see cref="Win32Exception"/> if it is false
        /// </summary>
        /// <param name="result">The flag to validate</param>
        private static void ValidateResult(bool result)
        {
            if (!result)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }
    }
}