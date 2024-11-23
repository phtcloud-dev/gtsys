
#include <ntifs.h>
#include <ntddk.h>
#include <ntifs.h>
#include <windef.h>




NTKERNELAPI UCHAR* PsGetProcessImageFileName(IN PEPROCESS Process);
NTKERNELAPI NTSTATUS PsSuspendProcess(PEPROCESS Proc);
NTKERNELAPI NTSTATUS PsResumeProcess(PEPROCESS proc);
NTKERNELAPI HANDLE PsGetProcessInheritedFromUniqueProcessId(IN PEPROCESS Process);
NTSYSAPI NTSTATUS NTAPI ZwQueryInformationProcess(IN HANDLE ProcessHandle, IN PROCESSINFOCLASS ProcessInformationClass, OUT PVOID ProcessInformation, IN ULONG ProcessInformationLength, IN PULONG ReturnLength);
NTKERNELAPI UCHAR* PsGetProcessImageFileName(__in PEPROCESS Process);


#define IOCTL_IO_GETSYS CTL_CODE(FILE_DEVICE_UNKNOWN,0x800,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_IO_GETFASYS CTL_CODE(FILE_DEVICE_UNKNOWN,0x801,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_IO_COPY CTL_CODE(FILE_DEVICE_UNKNOWN,0x802,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_IO_PID CTL_CODE(FILE_DEVICE_UNKNOWN,0x803,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_IO_SAPID CTL_CODE(FILE_DEVICE_UNKNOWN,0x804,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_IO_SETPID CTL_CODE(FILE_DEVICE_UNKNOWN,0x805,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_IO_INFO CTL_CODE(FILE_DEVICE_UNKNOWN,0x806,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_IO_SUSPID CTL_CODE(FILE_DEVICE_UNKNOWN,0x807,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_IO_RESPID CTL_CODE(FILE_DEVICE_UNKNOWN,0x808,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_IO_KILLPID CTL_CODE(FILE_DEVICE_UNKNOWN,0x809,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_IO_RAMPID CTL_CODE(FILE_DEVICE_UNKNOWN,0x810,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_IO_REBOOT CTL_CODE(FILE_DEVICE_UNKNOWN,0x811,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_IO_SHUTDOWN CTL_CODE(FILE_DEVICE_UNKNOWN,0x812,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_IO_SETPA CTL_CODE(FILE_DEVICE_UNKNOWN,0x813,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_IO_GETALLPID CTL_CODE(FILE_DEVICE_UNKNOWN,0x814,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_IO_ROOTFULL CTL_CODE(FILE_DEVICE_UNKNOWN,0x815,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_IO_NOUSE CTL_CODE(FILE_DEVICE_UNKNOWN,0x816,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_IO_SHUTDOWNHAL CTL_CODE(FILE_DEVICE_UNKNOWN,0x817,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_IO_REBOTHAL CTL_CODE(FILE_DEVICE_UNKNOWN,0x818,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_IO_ADDPROPID CTL_CODE(FILE_DEVICE_UNKNOWN,0x819,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_IO_DELPROPID CTL_CODE(FILE_DEVICE_UNKNOWN,0x820,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_IO_LISTPROPID CTL_CODE(FILE_DEVICE_UNKNOWN,0x821,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_IO_ADDALLHPID CTL_CODE(FILE_DEVICE_UNKNOWN,0x822,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_IO_DELALLHPID CTL_CODE(FILE_DEVICE_UNKNOWN,0x823,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_IO_LISTALLHPID CTL_CODE(FILE_DEVICE_UNKNOWN,0x824,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_IO_OBREG CTL_CODE(FILE_DEVICE_UNKNOWN,0x825,METHOD_BUFFERED,FILE_ANY_ACCESS)


#define PROCESS_TERMINATE                  (0x0001)
#define PROCESS_CREATE_THREAD              (0x0002)
#define PROCESS_SET_SESSIONID              (0x0004)
#define PROCESS_VM_OPERATION               (0x0008)
#define PROCESS_VM_READ                    (0x0010)
#define PROCESS_VM_WRITE                   (0x0020)
#define PROCESS_DUP_HANDLE                 (0x0040)
#define PROCESS_CREATE_PROCESS             (0x0080)
#define PROCESS_SET_QUOTA                  (0x0100)
#define PROCESS_SET_INFORMATION            (0x0200)
#define PROCESS_QUERY_INFORMATION          (0x0400)
#define PROCESS_SUSPEND_RESUME             (0x0800)
#define PROCESS_QUERY_LIMITED_INFORMATION  (0x1000)
#define PROCESS_SET_LIMITED_INFORMATION    (0x2000)

typedef struct _KLDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	PVOID ExceptionTable;
	ULONG ExceptionTableSize;

	PVOID GpValue;
	PVOID NonPagedDebugInfo;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT __Unused5;
	PVOID SectionPointer;
	ULONG CheckSum;

	PVOID LoadedImports;
	PVOID PatchInformation;
} KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;



PVOID g_RegistrationHandle = NULL;


PVOID LookupProcess(HANDLE Pid);
typedef struct
{
	DWORD orgpid;
	DWORD newpid;
}newpiddata;

typedef struct
{
	DWORD pid;
	DWORD level;
}ppldata;

typedef struct
{
	int suc;
	DWORD father;
	DWORD token;
	DWORD ppl;
	DWORD timer;
	char* name[256];
	char* path[1024];
}pidinfo;

typedef struct
{
	int suc;
	DWORD pid;
	DWORD father;
	DWORD token;
	DWORD ppl;
	DWORD timer;
	char* name[256];
	char* path[1024];
	int end;
}pidall;


NTSTATUS CreateDriverObject(IN PDRIVER_OBJECT pDriver)
{
	NTSTATUS Status;
	PDEVICE_OBJECT pDevObj;
	UNICODE_STRING DriverName;
	UNICODE_STRING SymLinkName;


	RtlInitUnicodeString(&DriverName, L"\\Device\\IO::SYS");
	Status = IoCreateDevice(pDriver, 0, &DriverName, FILE_DEVICE_UNKNOWN, 0, TRUE, &pDevObj);


	pDevObj->Flags |= DO_BUFFERED_IO;


	RtlInitUnicodeString(&SymLinkName, L"\\??\\IO::SYS");
	Status = IoCreateSymbolicLink(&SymLinkName, &DriverName);
	return STATUS_SUCCESS;
}


NTSTATUS DispatchCreate(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	DbgPrint("[gtsys]IRP_MJ_CREATE\n");
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}


NTSTATUS DispatchClose(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	DbgPrint("[gtsys]IRP_MJ_CLOSE\n");
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}



BOOL EnumProcesssys(DWORD i);
BOOL EnumProcesssysfa(DWORD i);
BOOL EnumProcesscopy(DWORD i, DWORD g);
BOOL GETProcesscopy(DWORD i);
BOOL ProtectionProcesscopy(DWORD i, DWORD g);
BOOL SETProcesscopy(DWORD i, DWORD g);
BOOL ResumeProcess(ULONG pid);
BOOL SusPendProcess(ULONG pid);
BOOL ZwKillProcess(ULONG pid);
BOOL MemKillProcess(HANDLE pid);
UINT_PTR GETProcesstoken(DWORD i);
UINT_PTR GETProcessPPL(DWORD i);
char* GETProcessNAME(DWORD i);
char* GetFullFileName(ULONG upid);
BOOL SetProcessfather(DWORD i, DWORD g);
DWORD GetAllProcess(DWORD lastpid);
BOOL getProcesssysfa(DWORD i);
BOOLEAN get_PspCidTable(ULONG64* tableAddr);
BOOL parse_table_3(ULONG64 BaseAddr, int table1, int table2, int table3);
BOOL parse_table_2(ULONG64 BaseAddr, INT index2, int table1, int table2);
BOOL parse_table_1(ULONG64 BaseAddr, INT index1, INT index2, int table1);
DWORD GETTIMER(DWORD i);

VOID ForceReboot()
{
	typedef void(__fastcall* FCRB)(void);
	/*
	mov al, 0FEh
	out 64h, al
	ret
	*/
	FCRB fcrb = NULL;
	UCHAR shellcode[6] = "\xB0\xFE\xE6\x64\xC3";
	fcrb = ExAllocatePool(NonPagedPool, 5);
	memcpy(fcrb, shellcode, 5);
	fcrb();
}



VOID ForceShutdown()
{
	typedef void(__fastcall* FCRB)(void);
	/*
	mov ax,2001h
	mov dx,1004h
	out dx,ax
	ret
	*/
	FCRB fcrb = NULL;
	UCHAR shellcode[12] = "\x66\xB8\x01\x20\x66\xBA\x04\x10\x66\xEF\xC3";
	fcrb = ExAllocatePool(NonPagedPool, 11);
	memcpy(fcrb, shellcode, 11);
	fcrb();
}


#pragma once

typedef enum _FIRMWARE_REENTRY {
	HalHaltRoutine,
	HalPowerDownRoutine,
	HalRestartRoutine,
	HalRebootRoutine,
	HalInteractiveModeRoutine,
	HalMaximumRoutine
} FIRMWARE_REENTRY, * PFIRMWARE_REENTRY;


NTKERNELAPI VOID NTAPI HalReturnToFirmware(
	LONG lReturnType
);


VOID ComputerPowerOffByHal()
{
	HalReturnToFirmware(HalPowerDownRoutine);
}

VOID ComputerResetByHal()
{
	HalReturnToFirmware(HalRebootRoutine);
}


#define UNIX_TIME_OFFSET 11644473600LL 
LONGLONG ConvertToUnixTimestamp(LARGE_INTEGER createTime) {


	return (createTime.QuadPart / 10000000LL) - UNIX_TIME_OFFSET;
}

DWORD procpidex[] = { 0,0,0,0,0,0,0,0,0,0 };
DWORD allhandpidex[] = { 0,0,0,0,0,0,0,0,0,0 };

OB_PREOP_CALLBACK_STATUS
PreOperationCallback(_In_ PVOID RegistrationContext,
	_Inout_ POB_PRE_OPERATION_INFORMATION PreInfo)
{


	PEPROCESS process = (PEPROCESS)PreInfo->Object;


	HANDLE pid = PsGetProcessId((PEPROCESS)PreInfo->Object);

	for (int m = 0; m < sizeof(procpidex) / sizeof(procpidex[0]); m++) {
		if (pid == procpidex[m]) {
			if (PreInfo->Operation == OB_OPERATION_HANDLE_CREATE)
			{
				PreInfo->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_TERMINATE;
				PreInfo->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_OPERATION;
				PreInfo->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_READ;
				PreInfo->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_WRITE;
				PreInfo->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_SUSPEND_RESUME;
				PreInfo->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_SET_QUOTA;
				PreInfo->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_SET_INFORMATION;
				PreInfo->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_QUERY_LIMITED_INFORMATION;
				PreInfo->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_QUERY_INFORMATION;
				PreInfo->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_DUP_HANDLE;
				PreInfo->Parameters->CreateHandleInformation.OriginalDesiredAccess &= ~PROCESS_TERMINATE;
				PreInfo->Parameters->CreateHandleInformation.OriginalDesiredAccess &= ~PROCESS_VM_OPERATION;
				PreInfo->Parameters->CreateHandleInformation.OriginalDesiredAccess &= ~PROCESS_VM_READ;
				PreInfo->Parameters->CreateHandleInformation.OriginalDesiredAccess &= ~PROCESS_VM_WRITE;
				PreInfo->Parameters->CreateHandleInformation.OriginalDesiredAccess &= ~PROCESS_SUSPEND_RESUME;
				PreInfo->Parameters->CreateHandleInformation.OriginalDesiredAccess &= ~PROCESS_SET_QUOTA;
				PreInfo->Parameters->CreateHandleInformation.OriginalDesiredAccess &= ~PROCESS_SET_INFORMATION;
				PreInfo->Parameters->CreateHandleInformation.OriginalDesiredAccess &= ~PROCESS_QUERY_LIMITED_INFORMATION;
				PreInfo->Parameters->CreateHandleInformation.OriginalDesiredAccess &= ~PROCESS_QUERY_INFORMATION;
				PreInfo->Parameters->CreateHandleInformation.OriginalDesiredAccess &= ~PROCESS_DUP_HANDLE;
			}
			if (PreInfo->Operation == OB_OPERATION_HANDLE_DUPLICATE)
			{
				PreInfo->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_TERMINATE;
				PreInfo->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_VM_OPERATION;
				PreInfo->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_VM_READ;
				PreInfo->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_VM_WRITE;
				PreInfo->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_SUSPEND_RESUME;
				PreInfo->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_SET_QUOTA;
				PreInfo->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_SET_INFORMATION;
				PreInfo->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_QUERY_LIMITED_INFORMATION;
				PreInfo->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_QUERY_INFORMATION;
				PreInfo->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_DUP_HANDLE;
				PreInfo->Parameters->DuplicateHandleInformation.OriginalDesiredAccess &= ~PROCESS_TERMINATE;
				PreInfo->Parameters->DuplicateHandleInformation.OriginalDesiredAccess &= ~PROCESS_VM_OPERATION;
				PreInfo->Parameters->DuplicateHandleInformation.OriginalDesiredAccess &= ~PROCESS_VM_READ;
				PreInfo->Parameters->DuplicateHandleInformation.OriginalDesiredAccess &= ~PROCESS_VM_WRITE;
				PreInfo->Parameters->DuplicateHandleInformation.OriginalDesiredAccess &= ~PROCESS_SUSPEND_RESUME;
				PreInfo->Parameters->DuplicateHandleInformation.OriginalDesiredAccess &= ~PROCESS_SET_QUOTA;
				PreInfo->Parameters->DuplicateHandleInformation.OriginalDesiredAccess &= ~PROCESS_SET_INFORMATION;
				PreInfo->Parameters->DuplicateHandleInformation.OriginalDesiredAccess &= ~PROCESS_QUERY_LIMITED_INFORMATION;
				PreInfo->Parameters->DuplicateHandleInformation.OriginalDesiredAccess &= ~PROCESS_QUERY_INFORMATION;
				PreInfo->Parameters->DuplicateHandleInformation.OriginalDesiredAccess &= ~PROCESS_DUP_HANDLE;
			}
			return OB_PREOP_SUCCESS;
		}
		if (pid == allhandpidex[m]) {
			if (PreInfo->Operation == OB_OPERATION_HANDLE_CREATE)
			{
				PreInfo->Parameters->CreateHandleInformation.DesiredAccess = PROCESS_ALL_ACCESS;
				PreInfo->Parameters->CreateHandleInformation.OriginalDesiredAccess = PROCESS_ALL_ACCESS;
			}
			if (PreInfo->Operation == OB_OPERATION_HANDLE_DUPLICATE)
			{
				PreInfo->Parameters->DuplicateHandleInformation.DesiredAccess = PROCESS_ALL_ACCESS;
				PreInfo->Parameters->DuplicateHandleInformation.OriginalDesiredAccess = PROCESS_ALL_ACCESS;
			}
			return OB_PREOP_SUCCESS;
		}
	}
	return OB_PREOP_SUCCESS;
}

BOOL regob() {
	if (!g_RegistrationHandle)
	{
		OB_OPERATION_REGISTRATION obOperationRegistrations;
		obOperationRegistrations.ObjectType = PsProcessType;
		obOperationRegistrations.Operations |= OB_OPERATION_HANDLE_CREATE;
		obOperationRegistrations.Operations |= OB_OPERATION_HANDLE_DUPLICATE;
		obOperationRegistrations.PreOperation = PreOperationCallback;
		obOperationRegistrations.PostOperation = NULL;


		OB_CALLBACK_REGISTRATION obCallbackRegistration = { 0 };
		UNICODE_STRING altitude = { 0 };
		RtlInitUnicodeString(&altitude, L"4");
		obCallbackRegistration.Version = ObGetFilterVersion();
		obCallbackRegistration.OperationRegistrationCount = 1;
		obCallbackRegistration.RegistrationContext = NULL;
		obCallbackRegistration.Altitude = altitude;
		obCallbackRegistration.OperationRegistration = &obOperationRegistrations;



		ObRegisterCallbacks(&obCallbackRegistration, &g_RegistrationHandle);
		return TRUE;
	}
	return FALSE;
}

BOOL UNregob() {
	if (g_RegistrationHandle)
	{
		ObUnRegisterCallbacks(g_RegistrationHandle);
		g_RegistrationHandle = NULL;
		return TRUE;
	}
	return FALSE;
}


NTSTATUS DispatchIoctl(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
	PIO_STACK_LOCATION pIrpStack;
	ULONG uIoControlCode;
	PVOID pIoBuffer;
	ULONG uInSize;
	ULONG uOutSize;
	pIrpStack = IoGetCurrentIrpStackLocation(pIrp);
	uIoControlCode = pIrpStack->Parameters.DeviceIoControl.IoControlCode;
	pIoBuffer = pIrp->AssociatedIrp.SystemBuffer;
	uInSize = pIrpStack->Parameters.DeviceIoControl.InputBufferLength;
	uOutSize = pIrpStack->Parameters.DeviceIoControl.OutputBufferLength;
	DbgPrint("[GETSYS] uIoControlCode: %p \n", uIoControlCode);
	switch (uIoControlCode)
	{
	case IOCTL_IO_GETSYS:
	{
		DWORD dw = 0;
		DWORD ans = 0;
		memcpy(&dw, pIoBuffer, sizeof(DWORD));
		if (EnumProcesssys(dw)) {
			ans = 1;
		}
		memcpy(pIoBuffer, &ans, sizeof(DWORD));
		status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_IO_GETFASYS:
	{
		DWORD dw = 0;
		DWORD ans = 0;
		memcpy(&dw, pIoBuffer, sizeof(DWORD));
		DWORD pid = EnumProcesssysfa(dw);
		if (pid) {
			ans = pid;
		}
		memcpy(pIoBuffer, &ans, sizeof(DWORD));
		status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_IO_COPY:
	{
		newpiddata getinfo;
		DWORD ans = 0;
		memcpy(&getinfo, pIoBuffer, sizeof(newpiddata));
		if (EnumProcesscopy(getinfo.orgpid, getinfo.newpid)) {
			ans = 1;
		}
		memcpy(pIoBuffer, &ans, sizeof(DWORD));
		status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_IO_PID:
	{
		DWORD ans;
		DWORD input;
		memcpy(&input, pIoBuffer, sizeof(DWORD));
		if (GETProcesscopy(input)) {
			ans = 1;
		}
		memcpy(pIoBuffer, &ans, sizeof(DWORD));
		status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_IO_SAPID:
	{
		ppldata getppl;
		DWORD level;
		DWORD pid;
		DWORD ans = 0;
		int tmp = 0;
		memcpy(&getppl, pIoBuffer, sizeof(ppldata));
		pid = getppl.pid;
		switch (getppl.level) {
		case 0:
			level = 0x0;
			break;
		case 1:
			level = 0x11;
			break;
		case 2:
			level = 0x21;
			break;
		case 3:
			level = 0x31;
			break;
		case 4:
			level = 0x41;
			break;
		case 5:
			level = 0x51;
			break;
		case 6:
			level = 0x52;
			break;
		case 7:
			level = 0x61;
			break;
		case 8:
			level = 0x62;
			break;
		case 9:
			level = 0x72;
			break;
		default:
			tmp = 114514;
			break;
		}
		if (tmp != 114514) {
			if (ProtectionProcesscopy(pid, level)) {
				ans = 1;
			}
		}
		memcpy(pIoBuffer, &ans, sizeof(DWORD));
		status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_IO_SETPID:
	{
		newpiddata getinfo;
		DWORD ans = 0;
		memcpy(&getinfo, pIoBuffer, sizeof(newpiddata));
		if (SETProcesscopy(getinfo.orgpid, getinfo.newpid)) {
			ans = 1;
		}
		memcpy(pIoBuffer, &ans, sizeof(DWORD));
		status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_IO_SUSPID:
	{
		DWORD ans = 0;
		DWORD input;
		memcpy(&input, pIoBuffer, sizeof(DWORD));
		if (SusPendProcess(input)) {
			ans = 1;
		}
		memcpy(pIoBuffer, &ans, sizeof(DWORD));
		status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_IO_RESPID:
	{
		DWORD ans = 0;
		DWORD input;
		memcpy(&input, pIoBuffer, sizeof(DWORD));
		if (ResumeProcess(input)) {
			ans = 1;
		}
		memcpy(pIoBuffer, &ans, sizeof(DWORD));
		status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_IO_KILLPID:
	{
		DWORD ans = 0;
		DWORD input;
		memcpy(&input, pIoBuffer, sizeof(DWORD));
		if (ZwKillProcess(input)) {
			ans = 1;
		}
		memcpy(pIoBuffer, &ans, sizeof(DWORD));
		status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_IO_RAMPID:
	{
		DWORD ans = 0;
		DWORD input;
		memcpy(&input, pIoBuffer, sizeof(DWORD));
		if (MemKillProcess(input)) {
			ans = 1;
		}
		memcpy(pIoBuffer, &ans, sizeof(DWORD));
		status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_IO_INFO:
	{
		pidinfo data;
		DWORD input;
		memcpy(&input, pIoBuffer, sizeof(DWORD));
		PEPROCESS pCurrentEprocess = NULL;
		pCurrentEprocess = LookupProcess((HANDLE)input);
		if (pCurrentEprocess != NULL)
		{
			data.suc = 1;
			data.token = GETProcesstoken(input);
			data.ppl = GETProcessPPL(input);
			data.father = getProcesssysfa(input);
			strcpy(data.name, GETProcessNAME(input));
			strcpy(data.path, GetFullFileName(input));
			data.timer = GETTIMER(input);
			ObDereferenceObject(pCurrentEprocess);
		}
		memcpy(pIoBuffer, &data, sizeof(data));
		status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_IO_REBOOT:
	{
		ForceReboot();
		status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_IO_SHUTDOWN:
	{
		ForceShutdown();
		status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_IO_SETPA:
	{
		newpiddata getinfo;
		DWORD ans = 0;
		memcpy(&getinfo, pIoBuffer, sizeof(newpiddata));
		if (SetProcessfather(getinfo.orgpid, getinfo.newpid)) {
			ans = 1;
		}
		memcpy(pIoBuffer, &ans, sizeof(DWORD));
		status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_IO_GETALLPID:
	{
		pidall data;
		DWORD input;
		memcpy(&input, pIoBuffer, sizeof(DWORD));
		DbgPrint("[GETSYS] PID: %d\n", input);
		input = GetAllProcess(input);
		if (input != 0) {
			PEPROCESS pCurrentEprocess = NULL;
			pCurrentEprocess = LookupProcess((HANDLE)input);
			if (pCurrentEprocess != NULL)
			{
				data.suc = 1;
				data.pid = input;
				data.token = GETProcesstoken(input);
				data.ppl = GETProcessPPL(input);
				data.father = getProcesssysfa(input);
				strcpy(data.name, GETProcessNAME(input));
				strcpy(data.path, GetFullFileName(input));
				data.end = 0;
				data.timer = GETTIMER(input);
				ObDereferenceObject(pCurrentEprocess);
			}
		}
		else {
			data.end = 1;
		}
		memcpy(pIoBuffer, &data, sizeof(data));
		status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_IO_SHUTDOWNHAL:
	{
		ComputerPowerOffByHal();
		status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_IO_REBOTHAL:
	{
		ComputerResetByHal();
		status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_IO_ADDPROPID:
	{
		DWORD ans = 0;
		DWORD input;
		memcpy(&input, pIoBuffer, sizeof(DWORD));
		for (int m = 0; m < sizeof(procpidex) / sizeof(procpidex[0]); m++) {
			if (0 == procpidex[m]) {
				procpidex[m] = input;
				ans = 1;
				break;
			}
		}
		memcpy(pIoBuffer, &ans, sizeof(DWORD));
		status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_IO_DELPROPID:
	{
		DWORD ans = 0;
		DWORD input;
		memcpy(&input, pIoBuffer, sizeof(DWORD));
		for (int m = 0; m < sizeof(procpidex) / sizeof(procpidex[0]); m++) {
			if (input == procpidex[m]) {
				procpidex[m] = 0;
				ans = 1;
				break;
			}
		}
		memcpy(pIoBuffer, &ans, sizeof(DWORD));
		status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_IO_LISTPROPID:
	{
		DWORD input;


		memcpy(&input, pIoBuffer, sizeof(DWORD));

		memcpy(pIoBuffer, &procpidex, sizeof(procpidex));


		status = STATUS_SUCCESS;
		break;
	}

	case IOCTL_IO_ADDALLHPID:
	{
		DWORD ans = 0;
		DWORD input;


		memcpy(&input, pIoBuffer, sizeof(DWORD));


		for (int m = 0; m < sizeof(allhandpidex) / sizeof(allhandpidex[0]); m++) {
			if (0 == allhandpidex[m]) {
				allhandpidex[m] = input;
				ans = 1;
				break;
			}
		}


		memcpy(pIoBuffer, &ans, sizeof(DWORD));


		status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_IO_DELALLHPID:
	{
		DWORD ans = 0;
		DWORD input;


		memcpy(&input, pIoBuffer, sizeof(DWORD));


		for (int m = 0; m < sizeof(allhandpidex) / sizeof(allhandpidex[0]); m++) {
			if (input == allhandpidex[m]) {
				allhandpidex[m] = 0;
				ans = 1;
				break;
			}
		}


		memcpy(pIoBuffer, &ans, sizeof(DWORD));


		status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_IO_LISTALLHPID:
	{
		DWORD input;


		memcpy(&input, pIoBuffer, sizeof(DWORD));

		memcpy(pIoBuffer, &allhandpidex, sizeof(allhandpidex));


		status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_IO_OBREG:
	{
		DWORD input;
		DWORD ans = 0;

		memcpy(&input, pIoBuffer, sizeof(DWORD));

		if (input == 1) {
			ans = regob();
		}
		else {
			ans = UNregob();
		}
		memcpy(pIoBuffer, &ans, sizeof(DWORD));


		status = STATUS_SUCCESS;
		break;
	}


	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = uOutSize;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return status;
	}


	if (status == STATUS_SUCCESS)
		pIrp->IoStatus.Information = uOutSize;
	else
		pIrp->IoStatus.Information = 0;


	pIrp->IoStatus.Status = status;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return status;
}




PEPROCESS GetProcessNameByProcessId(HANDLE pid)
{
	PEPROCESS ProcessObj = NULL;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	Status = PsLookupProcessByProcessId(pid, &ProcessObj);
	if (NT_SUCCESS(Status))
		return ProcessObj;
	return NULL;
}



NTKERNELAPI UCHAR* PsGetProcessImageFileName(IN PEPROCESS Process);





PVOID LookupProcess(HANDLE Pid)
{
	PVOID eprocess = NULL;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	Status = PsLookupProcessByProcessId(Pid, &eprocess);
	if (NT_SUCCESS(Status))
		return eprocess;
	return NULL;
}

DWORD GetAllProcess(DWORD lastpid1)
{
	PEPROCESS eproc = NULL;
	for (DWORD lastpid = lastpid1; lastpid < 4294967292; lastpid += 4)
	{
		eproc = LookupProcess((HANDLE)lastpid);
		if (eproc != NULL)
		{
			STRING nowProcessnameString = { 0 };
			RtlInitString(&nowProcessnameString, PsGetProcessImageFileName(eproc));
			ObDereferenceObject(eproc);
			return lastpid;
		}
	}
	return 0;
}

BOOL SusPendProcess(ULONG pid)
{
	PEPROCESS pCurrentEprocess = NULL;
	pCurrentEprocess = LookupProcess((HANDLE)pid);
	if (pCurrentEprocess != NULL)
	{
		PsSuspendProcess(pCurrentEprocess);
		ObDereferenceObject(pCurrentEprocess);
		return TRUE;
	}
	return FALSE;
}

BOOL MemKillProcess(HANDLE pid)
{
	PEPROCESS proc = NULL;
	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
	PKAPC_STATE pApcState = NULL;


	PsLookupProcessByProcessId((HANDLE)pid, &proc);
	if (proc != NULL)
	{
		pApcState = (PKAPC_STATE)ExAllocatePoolWithTag(NonPagedPool, sizeof(PKAPC_STATE), '1111');
		if (NULL == pApcState)
		{
			ObDereferenceObject(proc);
			return TRUE;
		}
		__try {
			KeStackAttachProcess(proc, pApcState);
			for (int i = 0x10000; i < 0x20000000; i += PAGE_SIZE)
			{
				__try
				{
					memset((PVOID)i, 0, PAGE_SIZE);
				}
				__except (1)
				{
					;
				}
			}
			KeUnstackDetachProcess(pApcState);
			ObDereferenceObject(proc);
			return TRUE;
		}
		__except (1)
		{
			KeUnstackDetachProcess(pApcState);
			ObDereferenceObject(proc);
		}
	}
	return FALSE;
}

DWORD GETTIMER(DWORD i)
{
	PVOID eproc = NULL;
	eproc = LookupProcess(i);
	if (eproc == NULL) {
		return 0;
	}
	ULONG64 tmpe;
	LARGE_INTEGER createTime;
	TIME_FIELDS timeFields;
	tmpe = eproc;
	createTime.QuadPart = *(UINT_PTR*)(tmpe + 0x468);
	LONGLONG unixTimestamp = ConvertToUnixTimestamp(createTime);
	return (DWORD)unixTimestamp;
}

BOOL ZwKillProcess(ULONG pid)
{
	HANDLE ProcessHandle = NULL;
	OBJECT_ATTRIBUTES obj;
	PEPROCESS pCurrentEprocess = NULL;
	pCurrentEprocess = LookupProcess((HANDLE)pid);
	if (pCurrentEprocess != NULL)
	{
		CLIENT_ID cid = { 0 };
		NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
		InitializeObjectAttributes(&obj, NULL, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
		cid.UniqueProcess = (HANDLE)pid;
		cid.UniqueThread = 0;
		ntStatus = ZwOpenProcess(&ProcessHandle, GENERIC_ALL, &obj, &cid);
		if (NT_SUCCESS(ntStatus))
		{
			ZwTerminateProcess(ProcessHandle, 0);
			ZwClose(ProcessHandle);
			return TRUE;
		}
		ZwClose(ProcessHandle);
		return FALSE;
	}
	return FALSE;
}

BOOL ResumeProcess(ULONG pid)
{
	PEPROCESS pCurrentEprocess = NULL;
	pCurrentEprocess = LookupProcess((HANDLE)pid);
	if (pCurrentEprocess != NULL)
	{
		PsResumeProcess(pCurrentEprocess);
		ObDereferenceObject(pCurrentEprocess);
		return TRUE;
	}
	return FALSE;
}


BOOL SETProcesscopy(DWORD i, DWORD g)
{
	PVOID eproc = NULL;
	eproc = LookupProcess(i);
	if (eproc == NULL) {
		return FALSE;
	}
	ULONG64 tmp, tmp1;
	tmp = eproc;
	tmp1 = eproc;
	UINT_PTR token = *(UINT_PTR*)(tmp + 0x440);
	tmp = tmp + 0x440;
	tmp1 = tmp1 + 0x87a;
	token = 0x0000000000000000 ^ g;
	RtlCopyMemory((PVOID)(tmp), &token, sizeof(UINT_PTR));
	return TRUE;
}

BOOL ProtectionProcesscopy(DWORD i, DWORD g)
{
	PVOID eproc = NULL;
	eproc = LookupProcess(i);;
	if (eproc == NULL) {
		return FALSE;
	}
	ULONG64 tmp1;
	tmp1 = eproc;
	UINT_PTR Protection = g;
	tmp1 = tmp1 + 0x87a;
	RtlCopyMemory((PVOID)(tmp1), &Protection, sizeof(UINT_PTR));
	return TRUE;
}

BOOL GETProcesscopy(DWORD i)
{
	PVOID eproc = NULL;
	eproc = LookupProcess(i);
	if (eproc == NULL) {
		return FALSE;
	}
	ULONG64 tmp, tmp1;
	tmp = eproc;
	tmp1 = eproc;
	UINT_PTR token = *(UINT_PTR*)(tmp + 0x440);
	tmp = tmp + 0x440;
	tmp1 = tmp1 + 0x87a;
	token = 0x0000000000000000;
	RtlCopyMemory((PVOID)(tmp), &token, sizeof(UINT_PTR));
	return TRUE;
}

BOOL EnumProcesscopy(DWORD i, DWORD g)
{
	PVOID eproc = NULL;
	eproc = LookupProcess(g);
	if (eproc == NULL) {
		return FALSE;
	}
	ULONG64 tmp;
	tmp = eproc;
	UINT_PTR token = *(UINT_PTR*)(tmp + 0x4b8) & 0xfffffffffffffff0;
	eproc = LookupProcess(i);
	if (eproc != NULL) {
		tmp = eproc;
		ObDereferenceObject(eproc);
		tmp = tmp + 0x4b8;
		RtlCopyMemory((PVOID)(tmp), &token, sizeof(UINT_PTR));
		return TRUE;
	}
	return FALSE;
}

BOOL SetProcessfather(DWORD i, DWORD g)
{
	PVOID eproc = NULL;
	eproc = LookupProcess(i);
	if (eproc == NULL) {
		return FALSE;
	}
	ULONG64 tmp;
	tmp = eproc;
	UINT_PTR token = *(UINT_PTR*)(tmp + 0x540);
	tmp = eproc;
	ObDereferenceObject(eproc);
	tmp = tmp + 0x540;
	RtlCopyMemory((PVOID)(tmp), &g, sizeof(DWORD));
	return TRUE;
}

BOOL EnumProcesssys(DWORD i)
{
	PVOID eproc = NULL;
	eproc = LookupProcess(4);
	ULONG64 tmp;
	tmp = eproc;
	UINT_PTR token = *(UINT_PTR*)(tmp + 0x4b8) & 0xfffffffffffffff0;
	eproc = LookupProcess(i);
	if (eproc != NULL) {
		tmp = eproc;
		ObDereferenceObject(eproc);
		DWORD64 ulProcessNmae = (DWORD64)(tmp + 0x5a8);
		tmp = tmp + 0x4b8;
		RtlCopyMemory((PVOID)(tmp), &token, sizeof(UINT_PTR));
		return TRUE;
	}
	return FALSE;
}

BOOL EnumProcesssysfa(DWORD i)
{
	PVOID eproc = NULL;
	eproc = LookupProcess(i);
	DWORD fapid;
	if (eproc != NULL) {
		fapid = PsGetProcessInheritedFromUniqueProcessId(eproc);
		ObDereferenceObject(eproc);
		if (EnumProcesssys(fapid)) {
			return fapid;
		}
	}
	return FALSE;
}

BOOL getProcesssysfa(DWORD i)
{
	PVOID eproc = NULL;
	eproc = LookupProcess(i);
	DWORD fapid;
	if (eproc != NULL) {
		fapid = PsGetProcessInheritedFromUniqueProcessId(eproc);
		ObDereferenceObject(eproc);
		return fapid;
	}
	return FALSE;
}

UINT_PTR GETProcesstoken(DWORD i)
{
	PVOID eproc = NULL;
	eproc = LookupProcess(i);
	if (eproc != NULL) {
		ULONG64 tmp;
		tmp = eproc;
		UINT_PTR token = *(UINT_PTR*)(tmp + 0x4b8);
		return token;
	}
	return 0;
}

UINT_PTR GETProcessPPL(DWORD i)
{
	PVOID eproc = NULL;
	eproc = LookupProcess(i);
	if (eproc == NULL) {
		return 0;
	}
	ULONG64 tmp1;
	tmp1 = eproc;
	UINT_PTR Protection = *(UINT_PTR*)(tmp1 + 0x87a);
	return Protection;
}


char* GETProcessNAME(DWORD i)
{
	PVOID eproc = NULL;
	eproc = LookupProcess(i);
	if (eproc == NULL) {
		return NULL;
	}
	ULONG64 tmp1 = (ULONG64)eproc;
	char* namePtr = (char*)(tmp1 + 0x5a8);
	return namePtr;
}

char* GetFullFileName(ULONG upid) {
	ULONG need_size = 0;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PUNICODE_STRING ucd_image_name_ptr = NULL;
	PEPROCESS ppeprocess = NULL;
	HANDLE hProcessHandle = (HANDLE)0;
	status = PsLookupProcessByProcessId((HANDLE)upid, &ppeprocess);
	if (!NT_SUCCESS(status))
	{
		return "Can not find process path";
	}

	status = ObOpenObjectByPointer(
		ppeprocess,
		OBJ_KERNEL_HANDLE,
		0,
		0,
		*PsProcessType,
		KernelMode,
		&hProcessHandle);
	if (!NT_SUCCESS(status))
	{
		if (ppeprocess != NULL)
		{
			ObDereferenceObject(ppeprocess);
			ppeprocess = NULL;
		}
		return "Can not find process path";
	}

	status = ZwQueryInformationProcess(hProcessHandle, ProcessImageFileNameWin32, NULL, 0, &need_size);
	while (status == STATUS_INFO_LENGTH_MISMATCH)
	{
		if (ucd_image_name_ptr != NULL)
		{
			ExFreePoolWithTag(ucd_image_name_ptr, 'abcd');
			ucd_image_name_ptr = NULL;
		}
		ucd_image_name_ptr = (PUNICODE_STRING)ExAllocatePoolWithTag(PagedPool, need_size, 'abcd');
		if (ucd_image_name_ptr != NULL)
		{
			RtlZeroMemory(ucd_image_name_ptr, need_size);
		}
		else
		{

			if (ppeprocess != NULL)
			{
				ObDereferenceObject(ppeprocess);
				ppeprocess = NULL;
			}
			if (hProcessHandle != NULL)
			{
				ZwClose(hProcessHandle);
				hProcessHandle = NULL;
			}
			return "Can not find process path";
		}
		status = ZwQueryInformationProcess(hProcessHandle, ProcessImageFileNameWin32, ucd_image_name_ptr, need_size, &need_size);
	}
	if (ucd_image_name_ptr == NULL)
	{
		if (ppeprocess != NULL)
		{
			ObDereferenceObject(ppeprocess);
			ppeprocess = NULL;
		}
		if (hProcessHandle != NULL)
		{
			ZwClose(hProcessHandle);
			hProcessHandle = NULL;
		}
		return "Can not find process path";
	}
	if (ppeprocess != NULL)
	{
		ObDereferenceObject(ppeprocess);
		ppeprocess = NULL;
	}
	if (hProcessHandle != NULL)
	{
		ZwClose(hProcessHandle);
		hProcessHandle = NULL;
	}
	ANSI_STRING ansiString;
	RtlInitAnsiString(&ansiString, NULL);
	status = RtlUnicodeStringToAnsiString(&ansiString, ucd_image_name_ptr, 'abcd');
	return ansiString.Buffer;
}



VOID UnDriver(PDRIVER_OBJECT driver)
{
	PDEVICE_OBJECT pDev;
	UNICODE_STRING SymLinkName;
	pDev = driver->DeviceObject;
	IoDeleteDevice(pDev);
	RtlInitUnicodeString(&SymLinkName, L"\\??\\IO::SYS");
	IoDeleteSymbolicLink(&SymLinkName);
	if (g_RegistrationHandle)
	{
		ObUnRegisterCallbacks(g_RegistrationHandle);
		g_RegistrationHandle = NULL;
	}
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT Driver, PUNICODE_STRING RegistryPath)
{
	CreateDriverObject(Driver);
	Driver->DriverUnload = UnDriver;
	Driver->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
	Driver->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;
	Driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctl;
	PKLDR_DATA_TABLE_ENTRY ldr = (PKLDR_DATA_TABLE_ENTRY)Driver->DriverSection;
	ldr->Flags |= 0x20;

	DbgPrint(("by phtcloud \n"));
	Driver->DriverUnload = UnDriver;
	return STATUS_SUCCESS;
}