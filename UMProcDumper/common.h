#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <winioctl.h>
#include <algorithm>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
#include "../shared/protocol.h"

namespace kd {
namespace fs = std::filesystem;
class Handle {
    HANDLE value_ = INVALID_HANDLE_VALUE;
public:
    Handle() = default;
    explicit Handle(HANDLE value) : value_(value) {}
    ~Handle() { reset(); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    Handle(Handle&& other) noexcept : value_(other.value_) { other.value_ = INVALID_HANDLE_VALUE; }
    void reset(HANDLE value = INVALID_HANDLE_VALUE) {
        if (value_ != INVALID_HANDLE_VALUE && value_ != nullptr) CloseHandle(value_);
        value_ = value;
    }
    HANDLE get() const { return value_; }
    explicit operator bool() const { return value_ != INVALID_HANDLE_VALUE && value_ != nullptr; }
};
inline std::string Utf8(const std::wstring& text) {
    if (text.empty()) return {};
    int count = WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    std::string result(count, '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), result.data(), count, nullptr, nullptr);
    return result;
}
[[noreturn]] inline void WinError(const char* action, DWORD code = GetLastError()) {
    wchar_t* message = nullptr;
    FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, code, 0, reinterpret_cast<wchar_t*>(&message), 0, nullptr);
    std::string detail = message ? Utf8(message) : "Unknown Windows error";
    if (message) LocalFree(message);
    if (code == ERROR_ACCESS_DENIED) detail += " Run this command from an elevated terminal.";
    if (code == ERROR_INVALID_IMAGE_HASH) detail += " Windows requires a driver signed for this system.";
    throw std::runtime_error(std::string(action) + " (" + std::to_string(code) + "): " + detail);
}
inline fs::path ExeDirectory() {
    std::wstring path(32768, L'\0');
    DWORD n = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    if (!n || n >= path.size()) WinError("GetModuleFileName");
    path.resize(n);
    return fs::path(path).parent_path();
}
inline DWORD Number(const std::wstring& text, const char* label) {
    if (text.empty() || text.find_first_not_of(L"0123456789") != std::wstring::npos)
        throw std::runtime_error(std::string("Invalid ") + label);
    auto value = std::stoull(text);
    if (!value || value > MAXDWORD) throw std::runtime_error(std::string("Invalid ") + label);
    return static_cast<DWORD>(value);
}
extern volatile LONG Cancelled;
inline void CheckCancelled() { if (InterlockedCompareExchange(&Cancelled, 0, 0)) throw std::runtime_error("Cancelled"); }
}
