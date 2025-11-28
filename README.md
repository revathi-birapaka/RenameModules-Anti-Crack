# 🛡️ DotNet Module Cloaker (Anti-Dump / Anti-Debug)

**Rename Modules** is a C# library for protecting .NET applications. It performs dynamic renaming of modules (DLL and EXE) in the process memory (PEB), masking them as system files.

## 🛡️ Protects Against

This method complicates the operation and breaks the functionality of the following tools:

*   **Extreme Dumper / MegaDumper**
*   **dnSpy / dnSpyEx (Debugger)**
*   **And more...**

## 💡 Tip

For maximum protection efficiency, it is recommended to:

* Encrypt strings (String Encryption).
* Use Syscalls (direct system calls) instead of standard P/Invoke.

## 🛠️ Installation and Usage

1. Add the `RenameModules.cs` class to ur project.
2. Call the `Execute` method at the start of the program:

```csharp
ModuleCloaker.Execute();
