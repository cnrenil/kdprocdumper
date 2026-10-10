#pragma once
#include <ntifs.h>
#include "../shared/protocol.h"
#define KD_POOL_TAG 'pDdK'
typedef struct _KD_SESSION {
    // A kernel handle keeps the process object alive and avoids PID reuse.
    HANDLE Process;
    KD_IMAGE Image;
} KD_SESSION;
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD UnloadDriver;
