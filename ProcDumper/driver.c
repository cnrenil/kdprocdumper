#include "driver.h"

#include <ntstrsafe.h>
#include <windef.h>

#include "memory.h"

#define CHECK_NTSTATUS_AND_FAIL(_expr) \
    do { \
        status = (_expr); \
        if (!NT_SUCCESS(status)) { \
            KdPrintEx((0, 0, "Error encountered: %s, Status Code: 0x%X\n", #_expr, status)); \
            goto Fail; \
        } \
    } while (0)

static NTSTATUS CompleteIrp(_In_ PIRP Irp, _In_ NTSTATUS Status, _In_ ULONG_PTR Information)
{
	Irp->IoStatus.Status = Status;
	Irp->IoStatus.Information = Information;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Status;
}

static NTSTATUS CreateModuleNameString(_In_ PINPUT_DUMP_INFO InputInfo, _Out_ PUNICODE_STRING ModuleName)
{
	ANSI_STRING moduleNameAnsi;
	SIZE_T moduleNameLength;

	moduleNameLength = 0;
	while (moduleNameLength < PROC_DUMPER_MAX_MODULE_NAME && InputInfo->ModuleName[moduleNameLength] != '\0') {
		moduleNameLength++;
	}

	if (moduleNameLength == 0 || moduleNameLength == PROC_DUMPER_MAX_MODULE_NAME) {
		return STATUS_INVALID_PARAMETER;
	}

	RtlInitAnsiString(&moduleNameAnsi, InputInfo->ModuleName);
	return RtlAnsiStringToUnicodeString(ModuleName, &moduleNameAnsi, TRUE);
}

NTSTATUS DispatchCreate(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDeviceObject);
	KdPrint(("DispatchCreate\n"));
	return CompleteIrp(pIrp, STATUS_SUCCESS, 0);
}

NTSTATUS DispatchClose(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDeviceObject);
	KdPrint(("DispatchClose\n"));
	return CompleteIrp(pIrp, STATUS_SUCCESS, 0);
}

NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
	PIO_STACK_LOCATION pIoStackLocation;
	PINPUT_DUMP_INFO pInputDumpInfoBuffer;
	PVOID pOutBuffer;
	PVOID mappedOutBuffer;
	ULONG inBufferLength;
	ULONG outBufferLength;
	ULONG controlCode;
	NTSTATUS status;
	UNICODE_STRING moduleName;
	PEPROCESS pProcess;
	ULONG_PTR information;

	UNREFERENCED_PARAMETER(pDeviceObject);

	KdPrintEx((0, 0, "DispatchDeviceControl\n"));

	pIoStackLocation = IoGetCurrentIrpStackLocation(pIrp);
	pInputDumpInfoBuffer = (PINPUT_DUMP_INFO)pIrp->AssociatedIrp.SystemBuffer;
	pOutBuffer = pIrp->AssociatedIrp.SystemBuffer;
	mappedOutBuffer = NULL;
	inBufferLength = pIoStackLocation->Parameters.DeviceIoControl.InputBufferLength;
	outBufferLength = pIoStackLocation->Parameters.DeviceIoControl.OutputBufferLength;
	controlCode = pIoStackLocation->Parameters.DeviceIoControl.IoControlCode;
	status = STATUS_SUCCESS;
	information = 0;
	RtlZeroMemory(&moduleName, sizeof(moduleName));
	pProcess = NULL;

	switch (controlCode)
	{
	case IOCTL_MYDEVICE_DUMP:
	{
		KdPrintEx((0, 0, "IOCTL_MYDEVICE_DUMP\n"));

		if (inBufferLength < sizeof(INPUT_DUMP_INFO) || pInputDumpInfoBuffer == NULL || pIrp->MdlAddress == NULL || outBufferLength == 0) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		mappedOutBuffer = MmGetSystemAddressForMdlSafe(pIrp->MdlAddress, NormalPagePriority | MdlMappingNoExecute);
		if (mappedOutBuffer == NULL) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		status = PsLookupProcessByProcessId(ULongToHandle(pInputDumpInfoBuffer->ProcessId), &pProcess);
		if (!NT_SUCCESS(status)) {
			KdPrint(("PsLookupProcessByProcessId failed: 0x%X\n", status));
			break;
		}

		status = CreateModuleNameString(pInputDumpInfoBuffer, &moduleName);
		if (!NT_SUCCESS(status)) {
			break;
		}

		CHECK_NTSTATUS_AND_FAIL(DumpProcessMemory(pProcess, &moduleName, mappedOutBuffer, outBufferLength, &information));
		break;
	}
	case IOCTL_MYDEVICE_IMAGESIZE:
	{
		MODULE_INFO moduleInfo;
		KAPC_STATE apcState;

		KdPrint(("IOCTL_MYDEVICE_IMAGESIZE\n"));

		if (inBufferLength < sizeof(INPUT_DUMP_INFO) || pInputDumpInfoBuffer == NULL || pOutBuffer == NULL || outBufferLength < sizeof(ULONG)) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		status = PsLookupProcessByProcessId(ULongToHandle(pInputDumpInfoBuffer->ProcessId), &pProcess);
		if (!NT_SUCCESS(status)) {
			KdPrint(("PsLookupProcessByProcessId failed: 0x%X\n", status));
			break;
		}

		status = CreateModuleNameString(pInputDumpInfoBuffer, &moduleName);
		if (!NT_SUCCESS(status)) {
			break;
		}

		RtlZeroMemory(&moduleInfo, sizeof(moduleInfo));
		RtlZeroMemory(&apcState, sizeof(apcState));

			KeStackAttachProcess((PRKPROCESS)pProcess, &apcState);
		status = GetModuleBaseAddressInfo(pProcess, &moduleName, &moduleInfo);
		KeUnstackDetachProcess(&apcState);

		if (!NT_SUCCESS(status)) {
			break;
		}

		*(PULONG)pOutBuffer = moduleInfo.SizeOfImage;
		information = sizeof(ULONG);
		break;
	}
	case IOCTL_MYDEVICE_PRINT:
		KdPrint(("IOCTL_MYDEVICE_PRINT\n"));
		break;
	default:
		status = STATUS_INVALID_DEVICE_REQUEST;
		break;
	}

Fail:
	if (moduleName.Buffer != NULL) {
		RtlFreeUnicodeString(&moduleName);
	}

	if (pProcess != NULL) {
		ObDereferenceObject(pProcess);
	}

	return CompleteIrp(pIrp, status, information);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
	NTSTATUS status;
	PDEVICE_OBJECT pDeviceObject;
	UNICODE_STRING devName;
	UNICODE_STRING symLink;

	UNREFERENCED_PARAMETER(pRegistryPath);

	RtlInitUnicodeString(&devName, PROC_DUMPER_DEVICE_NAME);
	RtlInitUnicodeString(&symLink, PROC_DUMPER_DOSDEVICE_NAME);

	status = IoCreateDevice(
		pDriverObject,
		0,
		&devName,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		FALSE,
		&pDeviceObject);
	if (!NT_SUCCESS(status)) {
		KdPrint(("IoCreateDevice failed: 0x%X\n", status));
		return status;
	}

	status = IoCreateSymbolicLink(&symLink, &devName);
	if (!NT_SUCCESS(status)) {
		KdPrint(("IoCreateSymbolicLink failed: 0x%X\n", status));
		IoDeleteDevice(pDeviceObject);
		return status;
	}

	pDeviceObject->Flags |= DO_BUFFERED_IO;
	pDeviceObject->Flags |= DO_DIRECT_IO;
	pDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

	pDriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;
	pDriverObject->DriverUnload = UnloadDriver;

	return STATUS_SUCCESS;
}

VOID UnloadDriver(PDRIVER_OBJECT pDriverObject)
{
	UNICODE_STRING symLink;

	RtlInitUnicodeString(&symLink, PROC_DUMPER_DOSDEVICE_NAME);
	IoDeleteSymbolicLink(&symLink);

	if (pDriverObject->DeviceObject != NULL) {
		IoDeleteDevice(pDriverObject->DeviceObject);
	}
}
