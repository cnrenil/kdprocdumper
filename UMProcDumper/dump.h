#pragma once
#include "targets.h"
namespace kd {
struct DumpOptions {
    DWORD pid = 0;
    std::wstring module;
    fs::path output;
    fs::path driver = ExeDirectory() / L"ProcDumper.sys";
    DWORD chunk = KD_MAX_CHUNK;
    bool all = false, raw = false, force = false, noLoad = false, keep = false, strict = false, json = false;
};
int Dump(const DumpOptions& options);
}
