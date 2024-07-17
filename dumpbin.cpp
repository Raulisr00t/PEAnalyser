#include <Windows.h>
#include <iostream>
#include <winternl.h>
#include <WinBase.h>

using namespace std;

BOOL ReadPeFile(LPCSTR FileName, PBYTE* pPe, SIZE_T* sPe) {
	HANDLE hFile;
	PBYTE pBuff = NULL;
	DWORD dwFileSize = 0, dwNumberOfBytesRead;

	hFile = CreateFileA(FileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		cerr << "[!] Error Opening Target File" << endl;
		goto __EndOfFunction;
	}
	dwFileSize = GetFileSize(hFile, NULL);
	if (dwFileSize == 0) {
		cerr << "[!] Error in Target FileSize" << endl;
		cerr << "[!] Error:" << GetLastError() << endl;
		goto __EndOfFunction;
	}
	pBuff = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileSize);
	if (pBuff == NULL) {
		cerr << "[!] Error Heap Allocation" << endl;
		goto __EndOfFunction;
	}
	if (!ReadFile(hFile, pBuff, dwFileSize, &dwNumberOfBytesRead, NULL) || dwFileSize != dwNumberOfBytesRead) {
		cerr << "[!] Error in Reading File";
		cerr << "[!] Error:" << GetLastError() << endl;
		goto __EndOfFunction;
	}
	cout << "[+] DONE [+]" << endl;

__EndOfFunction:
	*pPe = (PBYTE)pBuff;
	*sPe = (SIZE_T)dwFileSize;
	if (hFile)
		CloseHandle(hFile);
	if (*pPe == NULL || *sPe == 0)
		return FALSE;

	return TRUE;
}

void ParsePE(PBYTE pPE) {
	PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pPE;
	if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
		return;
	}

	PIMAGE_NT_HEADERS pImgNTHdr = (PIMAGE_NT_HEADERS)(pPE + pImgDosHdr->e_lfanew);
	if (pImgNTHdr->Signature != IMAGE_NT_SIGNATURE) {
		return;
	}

	cout << "\n\t#####################[ FILE HEADER ]#####################\n\n";

	cout << "[+] PE File Type Detected as:";
	IMAGE_FILE_HEADER pImgFileHdr = pImgNTHdr->FileHeader;
	if (pImgFileHdr.Characteristics & IMAGE_FILE_DLL) {
		cout << "DLL" << endl;
	}
	else if (pImgFileHdr.Characteristics & IMAGE_SUBSYSTEM_NATIVE) {
		cout << "SYS" << endl;
	}
	else {
		cout << "EXE" << endl;
	}
	WORD architecture = pImgFileHdr.Machine;
	cout << "[+] File Architecture is:";

	if (architecture == IMAGE_FILE_MACHINE_I386) {
		cout << "x32" << endl;
	}
	else {
		cout << "x64" << endl;
	}
	cout << "[+] Number Of Sections:" << pImgFileHdr.NumberOfSections << endl;
	cout << "[+] Size Of The Optional Header:" << pImgFileHdr.SizeOfOptionalHeader << " Byte" << endl;

	cout << "\n\t#####################[ OPTIONAL HEADER ]#####################\n\n";
	IMAGE_OPTIONAL_HEADER ImgOptHdr = pImgNTHdr->OptionalHeader;
	if (ImgOptHdr.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC) {
		return;
	}

	cout << "[+] Size Of Code Section : " << ImgOptHdr.SizeOfCode << endl;
	cout << "[+] Address Of Code Section : " << (PVOID)(pPE + ImgOptHdr.BaseOfCode)
		<< "\n\t\t[RVA : 0x" << hex << ImgOptHdr.BaseOfCode << "]" << dec << endl;

	cout << "[+] Size Of Initialized Data : " << ImgOptHdr.SizeOfInitializedData << endl;
	cout << "[+] Size Of Unitialized Data : " << ImgOptHdr.SizeOfUninitializedData << endl;
	cout << "[+] Preferable Mapping Address : " << (PVOID)ImgOptHdr.ImageBase << endl;

	cout << "[+] Required Version : " << ImgOptHdr.MajorOperatingSystemVersion << "."
		<< ImgOptHdr.MinorOperatingSystemVersion << endl;

	cout << "[+] Address Of The Entry Point : " << (PVOID)(pPE + ImgOptHdr.AddressOfEntryPoint)
		<< "\n\t\t[RVA : 0x" << hex << ImgOptHdr.AddressOfEntryPoint << "]" << dec << endl;

	cout << "[+] Size Of The Image : " << ImgOptHdr.SizeOfImage << endl;
	cout << "[+] File CheckSum : 0x" << hex << ImgOptHdr.CheckSum << dec << endl;

	cout << "[+] Number of entries in the DataDirectory array : " << ImgOptHdr.NumberOfRvaAndSizes << endl;

	cout << "\n\t#####################[ DIRECTORIES ]#####################\n\n";

	cout << "[*] Export Directory At " << (PVOID)(pPE + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
		<< " Of Size : " << ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size
		<< "\n\t\t[RVA : 0x" << hex << ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress << "]" << dec << endl;

	cout << "[*] Import Directory At " << (PVOID)(pPE + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress)
		<< " Of Size : " << ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size
		<< "\n\t\t[RVA : 0x" << hex << ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress << "]" << dec << endl;

	cout << "[*] Resource Directory At " << (PVOID)(pPE + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress)
		<< " Of Size : " << ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size
		<< "\n\t\t[RVA : 0x" << hex << ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress << "]" << dec << endl;

	cout << "[*] Exception Directory At " << (PVOID)(pPE + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress)
		<< " Of Size : " << ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size
		<< "\n\t\t[RVA : 0x" << hex << ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress << "]" << dec << endl;

	cout << "[*] Base Relocation Table At " << (PVOID)(pPE + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress)
		<< " Of Size : " << ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size
		<< "\n\t\t[RVA : 0x" << hex << ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress << "]" << dec << endl;

	cout << "[*] TLS Directory At " << (PVOID)(pPE + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress)
		<< " Of Size : " << ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size
		<< "\n\t\t[RVA : 0x" << hex << ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress << "]" << dec << endl;

	cout << "[*] Import Address Table At " << (PVOID)(pPE + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress)
		<< " Of Size : " << ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size
		<< "\n\t\t[RVA : 0x" << hex << ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress << "]" << dec << endl;

	cout << "\n\t#####################[ SECTIONS ]#####################\n\n";

	PIMAGE_SECTION_HEADER pImgSecHdr = (PIMAGE_SECTION_HEADER)(((PBYTE)pImgNTHdr) + sizeof(IMAGE_NT_HEADERS));

	for (size_t i = 0; i < pImgNTHdr->FileHeader.NumberOfSections; i++) {
		cout << "[#] Section Name:" << (CHAR*)pImgSecHdr->Name << endl;
		cout << "\tSize:" << pImgSecHdr->SizeOfRawData << endl;
		cout << "\tRVA:0x" << hex << pImgSecHdr->VirtualAddress << endl;
		cout << "\tAddress:0x" << (PVOID)(pPE + pImgSecHdr->VirtualAddress) << endl;
		cout << "\tRelocations:" << pImgSecHdr->NumberOfRelocations;
		cout << "\tPermissions:";

		if (pImgSecHdr->Characteristics & IMAGE_SCN_MEM_READ) {
			cout << "PAGE_READONLY | ";
		}
		if (pImgSecHdr->Characteristics & IMAGE_SCN_MEM_WRITE && pImgSecHdr->Characteristics & IMAGE_SCN_MEM_READ) {
			cout << "PAGE_READWRITE | ";
		}
		if (pImgSecHdr->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
			cout << "PAGE_EXECUTE | ";
		}
		if (pImgSecHdr->Characteristics & IMAGE_SCN_MEM_READ && pImgSecHdr->Characteristics & IMAGE_SCN_MEM_WRITE && pImgSecHdr->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
			cout << "PAGE_EXECUTE_READWRITE";
		}
		cout << "\n\n";
		pImgSecHdr = (PIMAGE_SECTION_HEADER)((PBYTE)pImgSecHdr + (DWORD)sizeof(IMAGE_SECTION_HEADER));

	}
}

int main(int argc, char* argv[]) {
	if (argc < 2) {
		cerr << "[!] Usage:<dumpbin.exe> <FileName>" << endl;
		return -1;
	}

	PBYTE pPE = NULL;
	SIZE_T sPE = 0;
	LPCSTR FileName = argv[1];

	if (!ReadPeFile(FileName, &pPE, &sPE)) {
		return -1;
	}
	cout << "[+] Analyzing File: " << FileName << endl;
	ParsePE(pPE);

	cout << "[>>] PRESS <Enter> to Quit" << endl;
	cin.get();

	return 0;
}
