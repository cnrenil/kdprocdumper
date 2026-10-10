#include "targets.h"
#include <TlHelp32.h>
#include <cwctype>
#include <iomanip>
#include <sstream>

namespace kd {
namespace {
std::wstring Lower(std::wstring text) {
    std::transform(text.begin(), text.end(), text.begin(), [](wchar_t c) { return static_cast<wchar_t>(towlower(c)); }); return text;
}
Handle Snapshot(DWORD flags, DWORD pid) {
    for (int retry = 0; retry != 8; ++retry) {
        Handle result(CreateToolhelp32Snapshot(flags, pid));
        if (result) return result;
        if (GetLastError() != ERROR_BAD_LENGTH) WinError("CreateToolhelp32Snapshot");
        Sleep(10);
    }
    WinError("Module list kept changing", ERROR_BAD_LENGTH);
}
}
std::vector<Process> Processes(const std::wstring& filter) {
    auto snapshot = Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W entry{}; entry.dwSize = sizeof(entry);
    std::vector<Process> result;
    if (!Process32FirstW(snapshot.get(), &entry)) { if (GetLastError() == ERROR_NO_MORE_FILES) return result; WinError("Process32First"); }
    do {
        if (entry.th32ProcessID && Lower(entry.szExeFile).find(Lower(filter)) != std::wstring::npos)
            result.push_back({entry.th32ProcessID, entry.szExeFile});
    } while (Process32NextW(snapshot.get(), &entry));
    if (GetLastError() != ERROR_NO_MORE_FILES) WinError("Process32Next");
    std::sort(result.begin(), result.end(), [](const Process& a, const Process& b) { return a.pid < b.pid; });
    return result;
}
std::vector<Module> Modules(DWORD pid) {
    auto snapshot = Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    MODULEENTRY32W entry{}; entry.dwSize = sizeof(entry);
    std::vector<Module> result;
    if (!Module32FirstW(snapshot.get(), &entry)) { if (GetLastError() == ERROR_NO_MORE_FILES) return result; WinError("Module32First"); }
    do { result.push_back({reinterpret_cast<ULONGLONG>(entry.modBaseAddr), entry.modBaseSize, entry.szModule, entry.szExePath}); }
    while (Module32NextW(snapshot.get(), &entry));
    if (GetLastError() != ERROR_NO_MORE_FILES) WinError("Module32Next");
    return result;
}
DWORD FindProcess(const std::wstring& name) {
    DWORD found = 0;
    for (const auto& process : Processes()) if (_wcsicmp(process.name.c_str(), name.c_str()) == 0) {
        if (found) throw std::runtime_error("Multiple processes have that name; select one with --pid");
        found = process.pid;
    }
    if (!found) throw std::runtime_error("Process name not found");
    return found;
}
std::wstring SafeName(std::wstring name) {
    for (auto& c : name) if (c < 32 || std::wstring(L"<>:\"/\\|?*").find(c) != std::wstring::npos) c = L'_';
    while (!name.empty() && (name.back() == L'.' || name.back() == L' ')) name.pop_back();
    return name.empty() ? L"image" : name;
}
std::string Json(const std::wstring& value) {
    std::ostringstream out; out << '"';
    for (unsigned char c : Utf8(value)) {
        if (c == '"' || c == '\\') out << '\\' << c;
        else if (c < 32) out << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<unsigned>(c);
        else out << c;
    }
    out << '"'; return out.str();
}
}
