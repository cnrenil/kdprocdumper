#include "dump.h"
#include "service.h"
#include "pe.h"
#include <chrono>

namespace kd {
namespace {
template<class In, class Out> void Ioctl(HANDLE device, DWORD code, const In* input, Out& output) {
    DWORD returned = 0;
    if (!DeviceIoControl(device, code, const_cast<In*>(input), input ? sizeof(In) : 0, &output, sizeof(output), &returned, nullptr)) WinError("Driver request");
    if (returned != sizeof(output)) throw std::runtime_error("Invalid driver response length");
}
struct Result { fs::path path; ULONGLONG missing; DWORD size; double seconds; };
Result DumpOne(HANDLE device, const DumpOptions& options, const Module& module, const fs::path& path) {
    const auto start = std::chrono::steady_clock::now();
    KD_SELECT select{KD_PROTOCOL_VERSION, options.pid, module.base};
    KD_IMAGE image{};
    Ioctl(device, KD_IOCTL_SELECT, &select, image);
    if (!image.SizeOfImage || image.SizeOfImage > KD_MAX_IMAGE || image.BaseAddress != module.base || image.SizeOfImage != module.size)
        throw std::runtime_error("Module changed since enumeration; refresh and retry");
    OutputFile output(path, options.force);
    std::vector<BYTE> chunk(sizeof(KD_READ_RESULT) + options.chunk);
    ULONGLONG missing = 0;
    DWORD lastPercent = MAXDWORD;
    for (DWORD offset = 0; offset < image.SizeOfImage;) {
        CheckCancelled();
        KD_READ request{offset, std::min(options.chunk, image.SizeOfImage - offset)};
        DWORD returned = 0;
        if (!DeviceIoControl(device, KD_IOCTL_READ, &request, sizeof(request), chunk.data(),
            sizeof(KD_READ_RESULT) + request.Length, &returned, nullptr)) WinError("Read image chunk");
        auto result = reinterpret_cast<const KD_READ_RESULT*>(chunk.data());
        if (returned != sizeof(*result) + request.Length || result->Length != request.Length ||
            result->Copied > request.Length || result->Missing != request.Length - result->Copied || result->Reserved)
            throw std::runtime_error("Invalid chunk response");
        missing += result->Missing;
        if (options.strict && result->Missing) throw std::runtime_error("Unreadable pages encountered (--strict); output discarded");
        output.Write(chunk.data() + sizeof(*result), request.Length);
        offset += request.Length;
        DWORD percent = static_cast<DWORD>(100ull * offset / image.SizeOfImage);
        DWORD mode = 0;
        if (!options.json && percent != lastPercent && GetConsoleMode(GetStdHandle(STD_ERROR_HANDLE), &mode)) {
            std::cerr << '\r' << Utf8(module.name) << "  " << percent << "%   "; lastPercent = percent;
        }
    }
    if (lastPercent != MAXDWORD) std::cerr << '\n';
    output.Close();
    if (!options.raw) RepairFile(output.Temporary(), image.BaseAddress);
    output.Commit();
    return {fs::absolute(path), missing, image.SizeOfImage,
        std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count()};
}
}
int Dump(const DumpOptions& options) {
    auto modules = Modules(options.pid);
    if (!options.module.empty()) {
        modules.erase(std::remove_if(modules.begin(), modules.end(), [&](const Module& m) {
            return _wcsicmp(m.name.c_str(), options.module.c_str()) != 0;
        }), modules.end());
        if (modules.size() > 1) throw std::runtime_error("Ambiguous module name");
    } else if (!options.all && !modules.empty()) modules.resize(1);
    if (modules.empty()) throw std::runtime_error("No matching module found");
    ControlLock lock;
    DriverLease lease;
    if (!options.noLoad) lease.Start(options.driver);
    Handle device(CreateFileW(KD_DEVICE_PATH, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr));
    if (!device) WinError("Open driver device");
    KD_INFO info{};
    Ioctl<KD_INFO>(device.get(), KD_IOCTL_INFO, nullptr, info);
    if (info.Version != KD_PROTOCOL_VERSION || info.MaxChunk != KD_MAX_CHUNK) throw std::runtime_error("Driver/CLI protocol mismatch; unload the old driver and load the matching SYS");
    bool partial = false, failed = false;
    if (options.json) std::cout << '[';
    bool first = true;
    for (const auto& module : modules) {
        CheckCancelled();
        auto filename = std::to_wstring(options.pid) + L"_" + SafeName(module.name) + (options.raw ? L".raw.bin" : L".dump.exe");
        fs::path path = options.output.empty() ? fs::current_path() / L"Output" / filename :
            options.all ? options.output / filename : options.output;
        if (options.json) { if (!first) std::cout << ','; first = false; }
        try {
            auto result = DumpOne(device.get(), options, module, path);
            partial |= result.missing != 0;
            if (options.json) std::cout << "{\"module\":" << Json(module.name) << ",\"output\":" << Json(result.path.wstring())
                << ",\"size\":" << result.size << ",\"missing\":" << result.missing << ",\"seconds\":" << result.seconds << '}';
            else std::cout << Utf8(result.path.wstring()) << " | " << result.size << " bytes, " << result.missing
                << " unreadable (zero-filled), " << result.seconds << " s\n";
        } catch (const std::exception& e) {
            failed = true;
            std::cerr << Utf8(module.name) << ": " << e.what() << '\n';
            if (options.json) std::cout << "{\"module\":" << Json(module.name) << ",\"failed\":true}";
            if (!options.all) break;
        }
    }
    if (options.json) std::cout << "]\n";
    device.reset();
    if (options.keep && !failed) lease.Keep();
    lease.Finish();
    return failed ? 1 : partial ? 2 : 0;
}
}
