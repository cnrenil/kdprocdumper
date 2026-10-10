#pragma once
#include "common.h"
namespace kd {
class ControlLock {
    Handle mutex_;
public:
    ControlLock();
    ~ControlLock();
};
class DriverLease {
    SC_HANDLE manager_ = nullptr;
    SC_HANDLE service_ = nullptr;
    bool created_ = false;
    bool started_ = false;
public:
    DriverLease() = default;
    DriverLease(const DriverLease&) = delete;
    DriverLease& operator=(const DriverLease&) = delete;
    ~DriverLease();
    void Start(const fs::path& path);
    void Keep() { started_ = created_ = false; }
    void Finish();
};
std::wstring DriverStatus();
void UnloadDriver(bool remove);
}
