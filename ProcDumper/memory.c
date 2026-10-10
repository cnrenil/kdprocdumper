#include "memory.h"
#include <ntimage.h>

#ifndef PROCESS_QUERY_INFORMATION
#define PROCESS_QUERY_INFORMATION 0x0400
#endif
#ifndef PROCESS_VM_READ
#define PROCESS_VM_READ 0x0010
#endif
#ifndef MEM_IMAGE
#define MEM_IMAGE 0x01000000
#endif

static BOOLEAN UserRange(ULONGLONG Address, SIZE_T Length)
{
    ULONGLONG highest = (ULONGLONG)(ULONG_PTR)MmHighestUserAddress;
    return Address >= 0x10000 && Address <= highest && Length != 0 && Length - 1 <= highest - Address;
}

static NTSTATUS CopyAttached(PVOID Target, ULONGLONG Source, SIZE_T Length, PSIZE_T Copied)
{
    MM_COPY_ADDRESS address;
    address.VirtualAddress = (PVOID)(ULONG_PTR)Source;
    return MmCopyMemory(Target, address, Length, MM_COPY_MEMORY_VIRTUAL, Copied);
}

NTSTATUS KdSelectImage(KD_SESSION* Session, const KD_SELECT* Request)
{
    PEPROCESS process = NULL;
    HANDLE handle = NULL;
    KAPC_STATE apc;
    NTSTATUS status;
    MEMORY_BASIC_INFORMATION mbi;
    IMAGE_DOS_HEADER dos = {0};
    IMAGE_NT_HEADERS64 nt = {0};
    SIZE_T copied = 0;
    ULONG imageSize = 0;
    KD_IMAGE image = {0};
    // Failed selection invalidates the previous target.
    if (Session->Process != NULL) ZwClose(Session->Process);
    RtlZeroMemory(Session, sizeof(*Session));
    if (Request->Version != KD_PROTOCOL_VERSION || Request->ProcessId == 0 ||
        !UserRange(Request->BaseAddress, sizeof(dos))) return STATUS_INVALID_PARAMETER;
    status = PsLookupProcessByProcessId(ULongToHandle(Request->ProcessId), &process);
    if (!NT_SUCCESS(status)) return status;
    status = ObOpenObjectByPointer(process, OBJ_KERNEL_HANDLE, NULL,
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, *PsProcessType, KernelMode, &handle);
    if (!NT_SUCCESS(status)) { ObDereferenceObject(process); return status; }
    KeStackAttachProcess((PRKPROCESS)process, &apc);
    // Only an image allocation may be selected; no PEB offsets or user pointers are trusted.
    status = ZwQueryVirtualMemory(handle, (PVOID)(ULONG_PTR)Request->BaseAddress,
        MemoryBasicInformation, &mbi, sizeof(mbi), NULL);
    if (NT_SUCCESS(status) && (mbi.Type != MEM_IMAGE || mbi.State != MEM_COMMIT ||
        (ULONGLONG)(ULONG_PTR)mbi.AllocationBase != Request->BaseAddress)) status = STATUS_INVALID_ADDRESS;
    if (NT_SUCCESS(status)) status = CopyAttached(&dos, Request->BaseAddress, sizeof(dos), &copied);
    if (NT_SUCCESS(status) && (copied != sizeof(dos) || dos.e_magic != IMAGE_DOS_SIGNATURE ||
        dos.e_lfanew < (LONG)sizeof(dos) || dos.e_lfanew > 1024 * 1024 ||
        !UserRange(Request->BaseAddress, (SIZE_T)dos.e_lfanew + sizeof(nt)))) status = STATUS_INVALID_IMAGE_FORMAT;
    if (NT_SUCCESS(status)) status = CopyAttached(&nt, Request->BaseAddress + dos.e_lfanew, sizeof(nt), &copied);
    if (NT_SUCCESS(status)) {
        if (copied != sizeof(nt) || nt.Signature != IMAGE_NT_SIGNATURE ||
            (nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC &&
             nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)) status = STATUS_INVALID_IMAGE_FORMAT;
        else {
            // SizeOfImage has the same offset in PE32 and PE32+ optional headers.
            imageSize = nt.OptionalHeader.SizeOfImage;
            if (imageSize < (ULONG)dos.e_lfanew + sizeof(nt) || imageSize > KD_MAX_IMAGE ||
                !UserRange(Request->BaseAddress, imageSize)) status = STATUS_INVALID_IMAGE_FORMAT;
        }
    }
    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(process);
    if (!NT_SUCCESS(status)) { ZwClose(handle); return status; }
    image.BaseAddress = Request->BaseAddress;
    image.SizeOfImage = imageSize;
    image.Machine = nt.FileHeader.Machine;
    Session->Process = handle;
    Session->Image = image;
    return STATUS_SUCCESS;
}

NTSTATUS KdReadImage(KD_SESSION* Session, const KD_READ* Request, KD_READ_RESULT* Result, PUCHAR Data)
{
    PEPROCESS process;
    KAPC_STATE apc;
    NTSTATUS status;
    ULONG offset = 0, copiedTotal = 0;
    if (Session->Process == NULL) return STATUS_INVALID_DEVICE_STATE;
    if (Request->Length == 0 || Request->Length > KD_MAX_CHUNK ||
        Request->Offset >= Session->Image.SizeOfImage ||
        Request->Length > Session->Image.SizeOfImage - Request->Offset) return STATUS_INVALID_PARAMETER;
    status = ObReferenceObjectByHandle(Session->Process, PROCESS_VM_READ, *PsProcessType,
        KernelMode, (PVOID*)&process, NULL);
    if (!NT_SUCCESS(status)) return status;
    RtlZeroMemory(Result, sizeof(*Result));
    RtlZeroMemory(Data, Request->Length);
    KeStackAttachProcess((PRKPROCESS)process, &apc);
    while (offset < Request->Length) {
        MEMORY_BASIC_INFORMATION mbi;
        ULONGLONG source = Session->Image.BaseAddress + Request->Offset + offset;
        SIZE_T regionOffset, length, copied = 0;
        status = ZwQueryVirtualMemory(Session->Process, (PVOID)(ULONG_PTR)source,
            MemoryBasicInformation, &mbi, sizeof(mbi), NULL);
        if (!NT_SUCCESS(status)) {
            // The image can be concurrently unmapped or page out between requests.
            // Preserve the fixed-size stream contract by zero-filling one page and continue.
            length = min((SIZE_T)PAGE_SIZE, Request->Length - offset);
            offset += (ULONG)length;
            status = STATUS_SUCCESS;
            continue;
        }
        regionOffset = (SIZE_T)(source - (ULONGLONG)(ULONG_PTR)mbi.BaseAddress);
        if (regionOffset >= mbi.RegionSize) { status = STATUS_INVALID_ADDRESS; break; }
        length = min(mbi.RegionSize - regionOffset, Request->Length - offset);
        if (mbi.State == MEM_COMMIT && mbi.Type == MEM_IMAGE &&
            (ULONGLONG)(ULONG_PTR)mbi.AllocationBase == Session->Image.BaseAddress &&
            !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD))) {
            // Copy a whole region; after a raced-out page continue at the next page.
            status = CopyAttached(Data + offset, source, length, &copied);
            copiedTotal += (ULONG)copied;
            if (copied < length) {
                SIZE_T skip = PAGE_SIZE - (SIZE_T)((source + copied) & (PAGE_SIZE - 1));
                length = min(length, copied + skip);
            }
        }
        offset += (ULONG)length;
        status = STATUS_SUCCESS;
    }
    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(process);
    if (!NT_SUCCESS(status)) return status;
    Result->Length = Request->Length;
    Result->Copied = copiedTotal;
    Result->Missing = Request->Length - copiedTotal;
    return STATUS_SUCCESS;
}
