#include "service.h"

namespace kd {
namespace {
class ServiceHandle {
public:
    SC_HANDLE value;
    explicit ServiceHandle(SC_HANDLE h) : value(h) {}
    ~ServiceHandle() { if (value) CloseServiceHandle(value); }
};
SERVICE_STATUS_PROCESS Query(SC_HANDLE service) {
    SERVICE_STATUS_PROCESS state{}; DWORD size = 0;
    if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, reinterpret_cast<BYTE*>(&state), sizeof(state), &size))
        WinError("QueryServiceStatusEx");
    return state;
}
void WaitFor(SC_HANDLE service, DWORD desired) {
    const auto deadline = GetTickCount64() + 15000;
    for (;;) {
        auto state = Query(service);
        if (state.dwCurrentState == desired) return;
        if (state.dwCurrentState == SERVICE_STOPPED && desired == SERVICE_RUNNING)
            WinError("Driver stopped during startup", state.dwWin32ExitCode ? state.dwWin32ExitCode : ERROR_SERVICE_NOT_ACTIVE);
        if (GetTickCount64() >= deadline) WinError("Driver transition timed out", ERROR_TIMEOUT);
        Sleep(100);
    }
}
void Stop(SC_HANDLE service) {
    auto state = Query(service);
    if (state.dwCurrentState == SERVICE_STOPPED) return;
    if (state.dwCurrentState == SERVICE_START_PENDING) WaitFor(service, SERVICE_RUNNING);
    if (state.dwCurrentState != SERVICE_STOP_PENDING) {
        SERVICE_STATUS status{};
        if (!ControlService(service, SERVICE_CONTROL_STOP, &status) && GetLastError() != ERROR_SERVICE_NOT_ACTIVE)
            WinError("Stop driver (close any other device clients first)");
    }
    WaitFor(service, SERVICE_STOPPED);
}
fs::path ServicePath(SC_HANDLE service, bool* quoted = nullptr) {
    DWORD size = 0;
    QueryServiceConfigW(service, nullptr, 0, &size);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) WinError("QueryServiceConfig");
    std::vector<BYTE> data(size);
    auto config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(data.data());
    if (!QueryServiceConfigW(service, config, size, &size)) WinError("QueryServiceConfig");
    if (config->dwServiceType != SERVICE_KERNEL_DRIVER) throw std::runtime_error("ProcDumper service is not a kernel driver");
    std::wstring path = config->lpBinaryPathName;
    if (path.rfind(L"\\??\\", 0) == 0) path.erase(0, 4);
    bool hasQuotes = path.size() >= 2 && path.front() == L'"' && path.back() == L'"';
    if (quoted) *quoted = hasQuotes;
    if (hasQuotes) path = path.substr(1, path.size() - 2);
    if (path.rfind(L"\\??\\", 0) == 0) path.erase(0, 4);
    return path;
}
}
ControlLock::ControlLock() : mutex_(CreateMutexW(nullptr, FALSE, L"Global\\KDProcDumper.Control.v2")) {
    if (!mutex_) WinError("Create control mutex");
    DWORD result = WaitForSingleObject(mutex_.get(), 0);
    if (result != WAIT_OBJECT_0 && result != WAIT_ABANDONED) throw std::runtime_error("Another CLI is managing or using the driver; try again later");
}
ControlLock::~ControlLock() { ReleaseMutex(mutex_.get()); }
void DriverLease::Start(const fs::path& requested) {
    auto path = fs::canonical(requested);
    if (!fs::is_regular_file(path) || _wcsicmp(path.extension().c_str(), L".sys") != 0)
        throw std::runtime_error("--driver must name an existing SYS file");
    manager_ = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
    if (!manager_) WinError("OpenSCManager");
    constexpr DWORD access = SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_STOP | DELETE;
    bool repairPath = false;
    service_ = OpenServiceW(manager_, KD_SERVICE_NAME, access);
    if (!service_) {
        if (GetLastError() != ERROR_SERVICE_DOES_NOT_EXIST) WinError("OpenService");
        // A kernel driver ImagePath is a filename, not an executable command line.
        // Quotes become part of the name and make StartService fail with error 123.
        service_ = CreateServiceW(manager_, KD_SERVICE_NAME, L"KDProcDumper", access, SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, path.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);
        if (!service_) WinError("CreateService");
        created_ = true;
    } else {
        std::error_code error;
        bool same = fs::equivalent(ServicePath(service_, &repairPath), path, error);
        if (error || !same) throw std::runtime_error("Existing ProcDumper service uses a different SYS. Run 'driver unload --remove' first");
    }
    auto state = Query(service_);
    if (state.dwCurrentState == SERVICE_STOP_PENDING) WaitFor(service_, SERVICE_STOPPED);
    if (state.dwCurrentState == SERVICE_START_PENDING) { WaitFor(service_, SERVICE_RUNNING); return; }
    if (state.dwCurrentState == SERVICE_RUNNING) return;
    if (repairPath) {
        // Repair older installations only after validating the SYS and stopping state.
        ServiceHandle writable(OpenServiceW(manager_, KD_SERVICE_NAME, SERVICE_CHANGE_CONFIG));
        if (!writable.value) WinError("OpenService to repair driver path");
        if (!ChangeServiceConfigW(writable.value, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE,
            path.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr, nullptr))
            WinError("Repair driver service path");
    }
    if (!StartServiceW(service_, 0, nullptr)) {
        if (GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) WinError("StartService");
    } else started_ = true;
    WaitFor(service_, SERVICE_RUNNING);
}
void DriverLease::Finish() {
    if (started_) { Stop(service_); started_ = false; }
    if (created_) {
        if (!DeleteService(service_) && GetLastError() != ERROR_SERVICE_MARKED_FOR_DELETE) WinError("DeleteService");
        created_ = false;
    }
}
DriverLease::~DriverLease() {
    try { Finish(); } catch (const std::exception& e) { std::cerr << "Driver cleanup: " << e.what() << '\n'; }
    if (service_) CloseServiceHandle(service_);
    if (manager_) CloseServiceHandle(manager_);
}
std::wstring DriverStatus() {
    ServiceHandle manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!manager.value) WinError("OpenSCManager");
    ServiceHandle service(OpenServiceW(manager.value, KD_SERVICE_NAME, SERVICE_QUERY_STATUS));
    if (!service.value) {
        if (GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST) return L"not installed";
        WinError("OpenService");
    }
    switch (Query(service.value).dwCurrentState) {
    case SERVICE_RUNNING: return L"running";
    case SERVICE_STOPPED: return L"stopped";
    case SERVICE_START_PENDING: return L"starting";
    case SERVICE_STOP_PENDING: return L"stopping";
    default: return L"transitioning";
    }
}
void UnloadDriver(bool remove) {
    ControlLock lock;
    ServiceHandle manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!manager.value) WinError("OpenSCManager");
    ServiceHandle service(OpenServiceW(manager.value, KD_SERVICE_NAME,
        SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG | SERVICE_STOP | (remove ? DELETE : 0)));
    if (!service.value) { if (GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST) return; WinError("OpenService"); }
    (void)ServicePath(service.value);
    Stop(service.value);
    if (remove && !DeleteService(service.value) && GetLastError() != ERROR_SERVICE_MARKED_FOR_DELETE) WinError("DeleteService");
}
}
