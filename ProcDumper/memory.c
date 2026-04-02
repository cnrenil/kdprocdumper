#include "memory.h"
#include "driver.h"

#define KDPROC_PROCESS_VM_OPERATION 0x0008
#define KDPROC_PROCESS_VM_READ      0x0010

#define PAGE_READABLE_MASK (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)

static BOOLEAN IsReadableProtection(_In_ ULONG Protect)
{
	ULONG effectiveProtect = Protect & ~(PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE);
	return (effectiveProtect & PAGE_READABLE_MASK) != 0;
}

static NTSTATUS CopyRegionWithTemporaryProtection(
	_In_ HANDLE ProcessHandle,
	_In_ PEPROCESS Process,
	_In_ PUCHAR SourceAddress,
	_Out_writes_bytes_(RegionSize) PUCHAR TargetAddress,
	_In_ SIZE_T RegionSize,
	_In_ ULONG OriginalProtect)
{
	NTSTATUS status;
	PVOID protectBase;
	SIZE_T protectSize;
	ULONG oldProtect;
	BOOLEAN protectionChanged;

	protectBase = SourceAddress;
	protectSize = RegionSize;
	oldProtect = 0;
	protectionChanged = FALSE;

	if (!IsReadableProtection(OriginalProtect) || (OriginalProtect & PAGE_GUARD) != 0) {
		status = ZwProtectVirtualMemory(ProcessHandle, &protectBase, &protectSize, PAGE_EXECUTE_READWRITE, &oldProtect);
		if (!NT_SUCCESS(status)) {
			KdPrintEx((0, 0, "ZwProtectVirtualMemory failed: 0x%X\n", status));
			return status;
		}
		protectionChanged = TRUE;
	}

	status = KeReadVirtualMemory(Process, SourceAddress, TargetAddress, RegionSize);

	if (protectionChanged) {
		ULONG ignoredProtect;
		PVOID restoreBase = SourceAddress;
		SIZE_T restoreSize = RegionSize;

		if (!NT_SUCCESS(ZwProtectVirtualMemory(ProcessHandle, &restoreBase, &restoreSize, OriginalProtect, &ignoredProtect))) {
			KdPrintEx((0, 0, "Failed to restore memory protection for %p\n", SourceAddress));
		}
	}

	return status;
}


NTSTATUS KeWriteVirtualMemory(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size)
{
	SIZE_T Bytes;
	if (NT_SUCCESS(MmCopyVirtualMemory(PsGetCurrentProcess(), SourceAddress, Process, TargetAddress, Size, KernelMode, &Bytes)))
		return STATUS_SUCCESS;

	return STATUS_UNSUCCESSFUL;
}

NTSTATUS KeReadVirtualMemory(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size)
{
	SIZE_T Bytes;
	if (NT_SUCCESS(MmCopyVirtualMemory(Process, SourceAddress, PsGetCurrentProcess(), TargetAddress, Size, KernelMode, &Bytes)))
		return STATUS_SUCCESS;

	return STATUS_UNSUCCESSFUL;
}

NTSTATUS GetModuleBaseAddressInfo(PEPROCESS Process, PUNICODE_STRING ModuleName, PMODULE_INFO BaseAddress)
{
	NTSTATUS Status;
	PPEB Peb;
	PPEB_LDR_DATA Ldr;
	PLDR_DATA_TABLE_ENTRY Module;
	PLIST_ENTRY ModuleList;

	Status = STATUS_SUCCESS;
	MODULE_INFO ModuleInfo = { 0 };

	Peb = PsGetProcessPeb(Process);
	if (Peb == NULL)
		return STATUS_UNSUCCESSFUL;


	Ldr = (PPEB_LDR_DATA)Peb->Ldr;
	if (Ldr == NULL)
		return STATUS_UNSUCCESSFUL;

	ModuleList = &Ldr->InMemoryOrderModuleList;
	ModuleList = ModuleList->Flink;

	while (ModuleList != &Ldr->InMemoryOrderModuleList)
	{
		Module = CONTAINING_RECORD(ModuleList, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		ModuleList = ModuleList->Flink;

		// print module dll name

		KdPrintEx((0, 0, "Module: %wZ\n", Module->BaseDllName));
		if (RtlCompareUnicodeString(&Module->BaseDllName, ModuleName, TRUE) == 0)
		{
			ModuleInfo.BaseAddress = Module->DllBase;
			ModuleInfo.EntryPoint = Module->EntryPoint;
			ModuleInfo.SizeOfImage = Module->SizeOfImage;
			ModuleInfo.FullDllName = Module->FullDllName;
			ModuleInfo.BaseDllName = Module->BaseDllName;
			break;
		}
	}

	// Check if moduleInfo is empty
	if (ModuleInfo.BaseAddress == NULL)
	{
		return STATUS_NOT_FOUND;
	}

	*BaseAddress = ModuleInfo;
	return Status;
}


NTSTATUS DumpProcessMemory(IN PEPROCESS Process, IN PUNICODE_STRING ModuleName, OUT PVOID OutBuffer, IN SIZE_T OutBufferSize, OUT PSIZE_T BytesWritten)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	MODULE_INFO BaseAddressInfo = { 0 };
	KAPC_STATE ApcState = { 0 };
	BOOLEAN attached = FALSE;
	HANDLE processHandle = NULL;

	if (BytesWritten != NULL)
	{
		*BytesWritten = 0;
	}
	__try {
		__try {
			OBJECT_ATTRIBUTES objectAttributes;
			CLIENT_ID clientId;
			PUCHAR moduleBase;
			SIZE_T moduleSize;
			SIZE_T copiedBytes;

			if (OutBuffer == NULL || OutBufferSize == 0 || BytesWritten == NULL)
			{
				Status = STATUS_INVALID_PARAMETER;
				__leave;
			}

			KeStackAttachProcess((PRKPROCESS)Process, &ApcState);
			attached = TRUE;
			Status = GetModuleBaseAddressInfo(Process, ModuleName, &BaseAddressInfo);
			if (!NT_SUCCESS(Status))
			{
				KdPrintEx((0, 0, "GetModuleBaseAddress failed: 0x%X\n", Status));
				__leave;
			}

			if (BaseAddressInfo.SizeOfImage > OutBufferSize)
			{
				Status = STATUS_BUFFER_TOO_SMALL;
				__leave;
			}

			KeUnstackDetachProcess(&ApcState);
			attached = FALSE;

			InitializeObjectAttributes(&objectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
			clientId.UniqueProcess = PsGetProcessId(Process);
			clientId.UniqueThread = NULL;

			Status = ZwOpenProcess(&processHandle, KDPROC_PROCESS_VM_OPERATION | KDPROC_PROCESS_VM_READ, &objectAttributes, &clientId);
			if (!NT_SUCCESS(Status))
			{
				KdPrintEx((0, 0, "ZwOpenProcess failed: 0x%X\n", Status));
				__leave;
			}

			moduleBase = (PUCHAR)BaseAddressInfo.BaseAddress;
			moduleSize = BaseAddressInfo.SizeOfImage;
			copiedBytes = 0;
			RtlZeroMemory(OutBuffer, moduleSize);

			KdPrintEx((0, 0, "Base address: 0x%p\n", BaseAddressInfo.BaseAddress));

			while (copiedBytes < moduleSize)
			{
				MEMORY_BASIC_INFORMATION mbi;
				PUCHAR currentAddress;
				SIZE_T remainingBytes;
				SIZE_T regionOffset;
				SIZE_T regionBytes;

				currentAddress = moduleBase + copiedBytes;
				remainingBytes = moduleSize - copiedBytes;
				RtlZeroMemory(&mbi, sizeof(mbi));

				Status = ZwQueryVirtualMemory(processHandle, currentAddress, MemoryBasicInformation, &mbi, sizeof(mbi), NULL);
				if (!NT_SUCCESS(Status))
				{
					KdPrintEx((0, 0, "ZwQueryVirtualMemory failed at %p: 0x%X\n", currentAddress, Status));
					__leave;
				}

				if (mbi.RegionSize == 0)
				{
					Status = STATUS_UNSUCCESSFUL;
					__leave;
				}

				regionOffset = (SIZE_T)(currentAddress - (PUCHAR)mbi.BaseAddress);
				if (regionOffset >= mbi.RegionSize)
				{
					Status = STATUS_UNSUCCESSFUL;
					__leave;
				}

				regionBytes = mbi.RegionSize - regionOffset;
				if (regionBytes > remainingBytes)
				{
					regionBytes = remainingBytes;
				}

				if (mbi.State != MEM_COMMIT)
				{
					copiedBytes += regionBytes;
					continue;
				}

				Status = CopyRegionWithTemporaryProtection(
					processHandle,
					Process,
					currentAddress,
					(PUCHAR)OutBuffer + copiedBytes,
					regionBytes,
					mbi.Protect);
				if (!NT_SUCCESS(Status))
				{
					KdPrintEx((0, 0, "CopyRegionWithTemporaryProtection failed at %p: 0x%X\n", currentAddress, Status));
					__leave;
				}

				copiedBytes += regionBytes;
			}

			*BytesWritten = moduleSize;
			Status = STATUS_SUCCESS;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			Status = GetExceptionCode();
			KdPrintEx((0, 0, "Exception: 0x%X\n", Status));
		}
	}
	__finally {
		if (processHandle != NULL)
		{
			ZwClose(processHandle);
		}

		if (attached)
		{
			KeUnstackDetachProcess(&ApcState);
		}

		return Status;
	}
}
