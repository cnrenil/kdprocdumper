#include "dump.h"
#include "service.h"
#include "pe.h"
#include "tui.h"
#include <map>
#include <set>

namespace kd {
volatile LONG Cancelled = 0;
namespace {
BOOL WINAPI ControlHandler(DWORD event) {
    if (event == CTRL_C_EVENT || event == CTRL_BREAK_EVENT) { InterlockedExchange(&Cancelled, 1); return TRUE; }
    return FALSE;
}
void Help() {
    std::cout << R"(KDProcDumper - one SYS backend, one CLI/TUI

  kdprocdumper                         Open keyboard TUI
  kdprocdumper tui [--driver PATH]
  kdprocdumper processes [--filter TEXT] [--json]
  kdprocdumper modules --pid PID [--json]
  kdprocdumper driver status
  kdprocdumper driver load [--driver PATH]
  kdprocdumper driver unload [--remove]
  kdprocdumper dump (--pid PID | --name EXE) [--module NAME | --all]
      [--output PATH] [--driver PATH] [--chunk-kib 4..1024]
      [--raw] [--strict] [--force] [--no-load | --keep-driver] [--json]
  kdprocdumper fix --input MEMORY_IMAGE --output PATH [--force]

Dump defaults to the main image and repairs PE headers internally.
--all treats --output as a directory; otherwise it is a filename.
Without --output: ./Output/<pid>_<module>.dump.exe (or .raw.bin).
The driver defaults to ProcDumper.sys beside this EXE. Dump automatically
loads it and restores its prior service state. --keep-driver keeps it loaded.
Use an elevated terminal for driver/dump commands; Windows signing applies.
--strict fails on any unreadable bytes; otherwise they are zero-filled.
--force explicitly allows replacing output. Ctrl+C cancels with cleanup.
Exit codes: 0 complete, 1 failure, 2 partial dump, 130 cancelled.
)";
}
class Arguments {
    std::map<std::wstring, std::wstring> values_;
    std::set<std::wstring> flags_;
public:
    Arguments(const std::vector<std::wstring>& args, size_t start,
        std::set<std::wstring> values, std::set<std::wstring> flags) {
        for (size_t i = start; i < args.size(); ++i) {
            const auto& key = args[i];
            if (values_.count(key) || flags_.count(key)) throw std::runtime_error("Duplicate option: " + Utf8(key));
            if (flags.count(key)) flags_.insert(key);
            else if (values.count(key)) {
                if (++i == args.size() || args[i].empty() || args[i].rfind(L"--", 0) == 0)
                    throw std::runtime_error("Missing value: " + Utf8(key));
                values_[key] = args[i];
            } else throw std::runtime_error("Unknown option: " + Utf8(key));
        }
    }
    bool Has(const wchar_t* key) const { return values_.count(key) || flags_.count(key); }
    std::wstring Get(const wchar_t* key, const std::wstring& fallback = {}) const {
        auto it = values_.find(key); return it == values_.end() ? fallback : it->second;
    }
    std::wstring Required(const wchar_t* key) const {
        if (!Has(key)) throw std::runtime_error("Required option: " + Utf8(key)); return Get(key);
    }
};
}
int Execute(const std::vector<std::wstring>& args) {
    if (args.empty()) return Tui(ExeDirectory() / L"ProcDumper.sys");
    const auto& command = args[0];
    if (command == L"--help" || command == L"-h" || command == L"help") { Help(); return 0; }
    if (command == L"--version") { std::cout << "KDProcDumper 2.0 (protocol " << KD_PROTOCOL_VERSION << ")\n"; return 0; }
    if (command == L"tui") {
        Arguments options(args, 1, {L"--driver"}, {});
        return Tui(options.Get(L"--driver", (ExeDirectory() / L"ProcDumper.sys").wstring()));
    }
    if (command == L"processes") {
        Arguments options(args, 1, {L"--filter"}, {L"--json"});
        auto list = Processes(options.Get(L"--filter"));
        bool json = options.Has(L"--json"), first = true;
        std::cout << (json ? "[" : "PID       PROCESS\n");
        for (const auto& process : list) {
            if (json) { if (!first) std::cout << ','; std::cout << "{\"pid\":" << process.pid << ",\"name\":" << Json(process.name) << '}'; }
            else std::cout << process.pid << "\t" << Utf8(process.name) << '\n';
            first = false;
        }
        if (json) std::cout << "]\n"; return 0;
    }
    if (command == L"modules") {
        Arguments options(args, 1, {L"--pid"}, {L"--json"});
        auto list = Modules(Number(options.Required(L"--pid"), "PID"));
        bool json = options.Has(L"--json"), first = true;
        std::cout << (json ? "[" : "BASE\tSIZE\tMODULE\tPATH\n");
        for (const auto& module : list) {
            if (json) {
                if (!first) std::cout << ',';
                // Encode addresses as strings to preserve all 64 bits in JSON consumers.
                std::cout << "{\"base\":\"0x" << std::hex << module.base << std::dec << "\",\"size\":" << module.size
                    << ",\"name\":" << Json(module.name) << ",\"path\":" << Json(module.path) << '}';
            } else std::cout << "0x" << std::hex << module.base << std::dec << '\t' << module.size << '\t' << Utf8(module.name) << '\t' << Utf8(module.path) << '\n';
            first = false;
        }
        if (json) std::cout << "]\n"; return 0;
    }
    if (command == L"driver") {
        if (args.size() < 2) throw std::runtime_error("Expected driver status, load, or unload");
        if (args[1] == L"status") {
            Arguments options(args, 2, {}, {}); std::cout << Utf8(DriverStatus()) << '\n'; return 0;
        }
        if (args[1] == L"load") {
            Arguments options(args, 2, {L"--driver"}, {});
            ControlLock lock; DriverLease lease;
            lease.Start(options.Get(L"--driver", (ExeDirectory() / L"ProcDumper.sys").wstring()));
            lease.Keep(); std::cout << "Driver running\n"; return 0;
        }
        if (args[1] == L"unload") {
            Arguments options(args, 2, {}, {L"--remove"});
            UnloadDriver(options.Has(L"--remove")); std::cout << "Driver stopped" << (options.Has(L"--remove") ? "; service removed\n" : "\n"); return 0;
        }
        throw std::runtime_error("Unknown driver command");
    }
    if (command == L"fix") {
        Arguments options(args, 1, {L"--input", L"--output"}, {L"--force"});
        FixFile(options.Required(L"--input"), options.Required(L"--output"), options.Has(L"--force"));
        std::cout << "Repaired PE: " << Utf8(options.Get(L"--output")) << '\n'; return 0;
    }
    if (command == L"dump") {
        Arguments options(args, 1, {L"--pid", L"--name", L"--module", L"--output", L"--driver", L"--chunk-kib"},
            {L"--all", L"--raw", L"--strict", L"--force", L"--no-load", L"--keep-driver", L"--json"});
        if (options.Has(L"--pid") == options.Has(L"--name")) throw std::runtime_error("Specify exactly one of --pid and --name");
        if (options.Has(L"--module") && options.Has(L"--all")) throw std::runtime_error("--module and --all are mutually exclusive");
        if (options.Has(L"--no-load") && options.Has(L"--keep-driver")) throw std::runtime_error("--no-load and --keep-driver are mutually exclusive");
        DumpOptions dump;
        DWORD kib = Number(options.Get(L"--chunk-kib", L"1024"), "chunk size");
        if (kib < 4 || kib > 1024) throw std::runtime_error("--chunk-kib must be 4..1024");
        dump.chunk = kib * 1024;
        dump.pid = options.Has(L"--pid") ? Number(options.Get(L"--pid"), "PID") : FindProcess(options.Get(L"--name"));
        dump.module = options.Get(L"--module"); dump.output = options.Get(L"--output");
        dump.driver = options.Get(L"--driver", dump.driver.wstring());
        dump.all = options.Has(L"--all"); dump.raw = options.Has(L"--raw"); dump.strict = options.Has(L"--strict");
        dump.force = options.Has(L"--force"); dump.noLoad = options.Has(L"--no-load"); dump.keep = options.Has(L"--keep-driver"); dump.json = options.Has(L"--json");
        return Dump(dump);
    }
    throw std::runtime_error("Unknown command. Use --help");
}
}
int wmain(int argc, wchar_t** argv) {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCtrlHandler(kd::ControlHandler, TRUE);
    try {
        int result = kd::Execute(std::vector<std::wstring>(argv + 1, argv + argc));
        return kd::Cancelled ? 130 : result;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << '\n'; return kd::Cancelled ? 130 : 1;
    }
}
