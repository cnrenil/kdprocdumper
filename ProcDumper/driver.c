#include "driver.h"
#include "memory.h"
#include <wdmsec.h>

// A KMUTEX leaves the caller at PASSIVE_LEVEL (unlike FAST_MUTEX).
static KMUTEX DeviceMutex;
static const GUID DeviceClass = {0xb3aa3462,0xe8e3,0x4b5c,{0xa0,0x67,0x47,0x8b,0x29,0x49,0x03,0x2d}};
C_ASSERT(sizeof(KD_SELECT) == 16);
C_ASSERT(sizeof(KD_IMAGE) == 16);
C_ASSERT(sizeof(KD_READ_RESULT) == 16);

static NTSTATUS Complete(PIRP Irp, NTSTATUS Status, ULONG_PTR Information)
{
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = NT_SUCCESS(Status) ? Information : 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

static NTSTATUS Dispatch(PDEVICE_OBJECT Device, PIRP Irp)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    KD_SESSION* session;
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR information = 0;
    UNREFERENCED_PARAMETER(Device);
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) return Complete(Irp, STATUS_INVALID_DEVICE_STATE, 0);
    KeWaitForSingleObject(&DeviceMutex, Executive, KernelMode, FALSE, NULL);
    session = stack->FileObject ? stack->FileObject->FsContext : NULL;
    switch (stack->MajorFunction) {
    case IRP_MJ_CREATE:
        session = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*session), KD_POOL_TAG);
        if (session == NULL) status = STATUS_INSUFFICIENT_RESOURCES;
        else { stack->FileObject->FsContext = session; status = STATUS_SUCCESS; }
        break;
    case IRP_MJ_CLEANUP:
    case IRP_MJ_CLOSE:
        if (session) {
            if (session->Process) ZwClose(session->Process);
            ExFreePoolWithTag(session, KD_POOL_TAG);
            stack->FileObject->FsContext = NULL;
        }
        status = STATUS_SUCCESS;
        break;
    case IRP_MJ_DEVICE_CONTROL:
        if (session) {
            ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
            ULONG input = stack->Parameters.DeviceIoControl.InputBufferLength;
            ULONG output = stack->Parameters.DeviceIoControl.OutputBufferLength;
            PVOID buffer = Irp->AssociatedIrp.SystemBuffer;
            if (code == KD_IOCTL_INFO && output >= sizeof(KD_INFO) && buffer) {
                KD_INFO info = {KD_PROTOCOL_VERSION, KD_MAX_CHUNK};
                RtlCopyMemory(buffer, &info, sizeof(info));
                information = sizeof(info);
                status = STATUS_SUCCESS;
            } else if (code == KD_IOCTL_SELECT && input == sizeof(KD_SELECT) && output >= sizeof(KD_IMAGE) && buffer) {
                KD_SELECT request;
                RtlCopyMemory(&request, buffer, sizeof(request));
                status = KdSelectImage(session, &request);
                if (NT_SUCCESS(status)) {
                    RtlCopyMemory(buffer, &session->Image, sizeof(session->Image));
                    information = sizeof(session->Image);
                }
            } else if (code == KD_IOCTL_READ && input == sizeof(KD_READ) && buffer && Irp->MdlAddress) {
                KD_READ request;
                KD_READ_RESULT* result;
                RtlCopyMemory(&request, buffer, sizeof(request));
                if (request.Length == 0 || request.Length > KD_MAX_CHUNK ||
                    output != sizeof(KD_READ_RESULT) + request.Length) { status = STATUS_INVALID_PARAMETER; break; }
                result = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority | MdlMappingNoExecute);
                if (!result) { status = STATUS_INSUFFICIENT_RESOURCES; break; }
                status = KdReadImage(session, &request, result, (PUCHAR)(result + 1));
                if (NT_SUCCESS(status)) information = sizeof(*result) + request.Length;
            } else status = STATUS_INVALID_PARAMETER;
        }
        break;
    }
    KeReleaseMutex(&DeviceMutex, FALSE);
    return Complete(Irp, status, information);
}

VOID UnloadDriver(PDRIVER_OBJECT Driver)
{
    UNICODE_STRING link = RTL_CONSTANT_STRING(L"\\DosDevices\\ProcDumper");
    IoDeleteSymbolicLink(&link);
    IoDeleteDevice(Driver->DeviceObject);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT Driver, PUNICODE_STRING RegistryPath)
{
    UNICODE_STRING name = RTL_CONSTANT_STRING(L"\\Device\\ProcDumper");
    UNICODE_STRING link = RTL_CONSTANT_STRING(L"\\DosDevices\\ProcDumper");
    UNICODE_STRING sddl = RTL_CONSTANT_STRING(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    PDEVICE_OBJECT device;
    NTSTATUS status;
    ULONG i;
    UNREFERENCED_PARAMETER(RegistryPath);
    KeInitializeMutex(&DeviceMutex, 0);
    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; ++i) Driver->MajorFunction[i] = Dispatch;
    Driver->DriverUnload = UnloadDriver;
    // Exclusive device use makes automatic unload ownership predictable across CLI instances.
    status = IoCreateDeviceSecure(Driver, 0, &name, FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN, TRUE, &sddl, &DeviceClass, &device);
    if (!NT_SUCCESS(status)) return status;
    status = IoCreateSymbolicLink(&link, &name);
    if (!NT_SUCCESS(status)) { IoDeleteDevice(device); return status; }
    device->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
}
