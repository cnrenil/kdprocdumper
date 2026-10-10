#pragma once
#include "driver.h"
NTSTATUS KdSelectImage(KD_SESSION* Session, const KD_SELECT* Request);
NTSTATUS KdReadImage(KD_SESSION* Session, const KD_READ* Request, KD_READ_RESULT* Result, PUCHAR Data);
