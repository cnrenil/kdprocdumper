#pragma once
// Include Windows.h/winioctl.h or ntifs.h first. Fixed-width wire ABI.
#define KD_PROTOCOL_VERSION 2u
#define KD_MAX_CHUNK (1024u * 1024u)
#define KD_MAX_IMAGE (1024u * 1024u * 1024u)
#define KD_DEVICE_PATH L"\\\\.\\ProcDumper"
#define KD_SERVICE_NAME L"ProcDumper"
#define KD_IOCTL_INFO CTL_CODE(FILE_DEVICE_UNKNOWN, 0x810, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define KD_IOCTL_SELECT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x811, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define KD_IOCTL_READ CTL_CODE(FILE_DEVICE_UNKNOWN, 0x812, METHOD_OUT_DIRECT, FILE_READ_DATA | FILE_WRITE_DATA)
#pragma pack(push, 8)
typedef struct _KD_INFO { ULONG Version; ULONG MaxChunk; } KD_INFO;
typedef struct _KD_SELECT { ULONG Version; ULONG ProcessId; ULONGLONG BaseAddress; } KD_SELECT;
typedef struct _KD_IMAGE { ULONGLONG BaseAddress; ULONG SizeOfImage; ULONG Machine; } KD_IMAGE;
typedef struct _KD_READ { ULONG Offset; ULONG Length; } KD_READ;
// Followed by Length bytes; unavailable bytes are zero, counted in Missing.
typedef struct _KD_READ_RESULT { ULONG Length; ULONG Copied; ULONG Missing; ULONG Reserved; } KD_READ_RESULT;
#pragma pack(pop)
