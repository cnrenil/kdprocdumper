#include "tui.h"
#include "dump.h"
#include "service.h"
#include "pe.h"
#include <conio.h>

namespace kd {
namespace {
void Clear() {
    HANDLE console = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO info{};
    if (!GetConsoleScreenBufferInfo(console, &info)) return;
    DWORD written = 0;
    COORD origin{0, info.srWindow.Top};
    DWORD cells = info.dwSize.X * (info.srWindow.Bottom - info.srWindow.Top + 1);
    FillConsoleOutputCharacterW(console, L' ', cells, origin, &written);
    FillConsoleOutputAttribute(console, info.wAttributes, cells, origin, &written);
    SetConsoleCursorPosition(console, origin);
}
int Key() {
    while (!_kbhit()) { CheckCancelled(); Sleep(30); }
    int key = _getwch();
    if (key == 0 || key == 224) return 256 + _getwch();
    if (key == 3) { InterlockedExchange(&Cancelled, 1); CheckCancelled(); }
    return key;
}
// -1 back, -2 refresh. A searchable, paginated keyboard selector without dependencies.
int Choose(const std::string& title, const std::vector<std::wstring>& rows, bool refresh = false) {
    size_t selected = 0;
    std::wstring filter;
    for (;;) {
        std::vector<size_t> visible;
        for (size_t i = 0; i < rows.size(); ++i) {
            std::wstring row = rows[i], needle = filter;
            std::transform(row.begin(), row.end(), row.begin(), towlower);
            std::transform(needle.begin(), needle.end(), needle.begin(), towlower);
            if (row.find(needle) != std::wstring::npos) visible.push_back(i);
        }
        if (selected >= visible.size()) selected = visible.empty() ? 0 : visible.size() - 1;
        CONSOLE_SCREEN_BUFFER_INFO info{};
        GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &info);
        size_t pageSize = static_cast<size_t>(std::max(3, info.srWindow.Bottom - info.srWindow.Top - 7));
        size_t page = selected / pageSize * pageSize;
        Clear();
        std::cout << "KDProcDumper  /  " << title << "\n\n";
        std::cout << "Up/Down: select  Enter: open  Esc: back  PgUp/PgDn: page" << (refresh ? "  F5: refresh" : "") << '\n';
        std::cout << "Type to filter; Backspace: erase | " << Utf8(filter) << "\n\n";
        for (size_t i = page; i < std::min(page + pageSize, visible.size()); ++i)
            std::cout << (i == selected ? " > " : "   ") << Utf8(rows[visible[i]]) << '\n';
        if (visible.empty()) std::cout << "   No matching entries\n";
        std::cout << "\n" << visible.size() << " entries" << std::flush;
        int key = Key();
        if (key == 27) return -1;
        if (key == 256 + 63 && refresh) return -2;
        if (key == 13 && !visible.empty()) return static_cast<int>(visible[selected]);
        if (key == 256 + 72 && selected) --selected;
        else if (key == 256 + 80 && selected + 1 < visible.size()) ++selected;
        else if (key == 256 + 73) selected = selected > pageSize ? selected - pageSize : 0;
        else if (key == 256 + 81 && !visible.empty()) selected = std::min(selected + pageSize, visible.size() - 1);
        else if (key == 8 && !filter.empty()) { filter.pop_back(); selected = 0; }
        else if (key >= 32 && (key < 256 || key > 511)) { filter += static_cast<wchar_t>(key); selected = 0; }
    }
}
std::wstring Prompt(const char* label) {
    std::cout << '\n' << label << std::flush;
    std::wstring text;
    for (;;) {
        int key = Key();
        if (key == 13) { std::cout << '\n'; return text; }
        if (key == 27) throw std::runtime_error("Input cancelled");
        if (key == 8 && !text.empty()) { text.pop_back(); std::cout << "\b \b" << std::flush; }
        else if (key >= 32 && (key < 256 || key > 511)) { text += static_cast<wchar_t>(key); std::cout << Utf8(std::wstring(1, static_cast<wchar_t>(key))) << std::flush; }
    }
}
void Pause() { std::cout << "\nPress any key to return..." << std::flush; (void)Key(); }
void PickDump(const fs::path& driver) {
    for (;;) {
        auto processes = Processes();
        std::vector<std::wstring> rows;
        for (const auto& process : processes) rows.push_back(std::to_wstring(process.pid) + L"  " + process.name);
        int p = Choose("Processes", rows, true);
        if (p == -1) return;
        if (p == -2) continue;
        for (;;) {
            auto modules = Modules(processes[p].pid);
            rows = {L"[Dump ALL modules]"};
            for (const auto& module : modules) rows.push_back(module.name + L"  (" + std::to_wstring(module.size / 1024) + L" KiB)");
            int m = Choose(Utf8(processes[p].name) + " / Modules", rows, true);
            if (m == -1) break;
            if (m == -2) continue;
            int mode = Choose("Output format", {L"Repaired PE (default)", L"Raw memory image", L"Repaired PE, fail if any page is unreadable"});
            if (mode < 0) continue;
            DumpOptions options;
            options.pid = processes[p].pid; options.driver = driver; options.all = m == 0;
            if (m) options.module = modules[m - 1].name;
            options.raw = mode == 1; options.strict = mode == 2;
            Clear();
            options.output = Prompt(options.all ? "Output directory [Enter = ./Output]: " : "Output filename [Enter = automatic]: ");
            int result = Dump(options);
            std::cout << (result == 0 ? "Complete\n" : result == 2 ? "Partial dump: unreadable bytes were zero-filled\n" : "Dump failed\n");
            Pause(); return;
        }
    }
}
}
int Tui(const fs::path& driver) {
    DWORD inputMode = 0, outputMode = 0;
    if (!GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &inputMode) || !GetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), &outputMode))
        throw std::runtime_error("TUI requires an interactive terminal. Use --help for CLI commands");
    for (;;) {
        CheckCancelled();
        std::string status;
        try { status = Utf8(DriverStatus()); } catch (...) { status = "unavailable"; }
        int action = Choose("Driver: " + status, {L"Browse processes and dump modules", L"Load driver", L"Unload driver",
            L"Unload driver and remove service", L"Repair a raw PE memory image", L"Exit"});
        if (action == -1 || action == 5) return 0;
        try {
            if (action == 0) { PickDump(driver); continue; }
            Clear();
            if (action == 1) { ControlLock lock; DriverLease lease; lease.Start(driver); lease.Keep(); std::cout << "Driver running\n"; }
            else if (action == 2 || action == 3) { UnloadDriver(action == 3); std::cout << "Driver stopped\n"; }
            else if (action == 4) {
                auto input = Prompt("Input memory image: "); auto output = Prompt("Output PE: ");
                if (input.empty() || output.empty()) throw std::runtime_error("Input and output paths are required");
                FixFile(input, output, false); std::cout << "PE repaired\n";
            }
        } catch (const std::exception& e) { std::cerr << "\nError: " << e.what() << '\n'; }
        Pause();
    }
}
}
