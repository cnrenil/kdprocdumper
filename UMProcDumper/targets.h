#pragma once
#include "common.h"
namespace kd {
struct Process { DWORD pid; std::wstring name; };
struct Module { ULONGLONG base; DWORD size; std::wstring name; std::wstring path; };
std::vector<Process> Processes(const std::wstring& filter = {});
std::vector<Module> Modules(DWORD pid);
DWORD FindProcess(const std::wstring& name);
std::wstring SafeName(std::wstring name);
std::string Json(const std::wstring& value);
}
