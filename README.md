# DumpBin
DumpBin is a command-line tool for analyzing Portable Executable (PE) files, such as EXE, DLL, and SYS files. This tool reads and parses the PE file, displaying detailed information about its structure, including the file header, optional header, directories, and sections.

## Features
1.Reads PE files and displays detailed information.
2.Identifies file type (EXE, DLL, SYS).
3.Displays architecture (x32, x64).
4.Shows number of sections and size of optional header.
5.Provides detailed information about the optional header, directories, and sections.

## Prerequisites
Windows operating system.
C++ compiler (e.g., Visual Studio).

### Compilation
To compile DumpBin, use the following command in a Visual Studio Developer Command Prompt:
```powershell
  cl /EHsc dumpbin.cpp
```
### Usage
To run DumpBin, use the following command:
```powershell
  dumpbin.exe <FileName>
```
### Example
```powershell
  dumpbin.exe C:\Users\your_path\file.exe
```
### Output
DumpBin displays the following information about the PE file:

File Header:

PE File Type (EXE, DLL, SYS)
File Architecture (x32, x64)
Number of Sections
Size of Optional Header
Optional Header:

Size of Code Section
Address of Code Section
Size of Initialized Data
Size of Uninitialized Data
Preferable Mapping Address
Required Version
Address of the Entry Point
Size of the Image
File CheckSum
Number of entries in the Data Directory array
Directories:

Export Directory
Import Directory
Resource Directory
Exception Directory
Base Relocation Table
TLS Directory
Import Address Table
Sections:

Section Name
Size
RVA (Relative Virtual Address)
Address
Relocations
Permissions (Read, Write, Execute)
Error Handling

DumpBin provides error messages for the following scenarios:

Error opening target file.
Error in target file size.
Error heap allocation.
Error reading file.

## Contribution
Feel free to contribute to this project by submitting issues or pull requests on the GitHub repository.

## License
This project is licensed under the MIT License.
