#include "pe.h"
#include <cstring>

namespace kd {
namespace {
void Require(bool condition, const char* reason) { if (!condition) throw std::runtime_error(std::string("Invalid memory-layout PE: ") + reason); }
bool Range(size_t offset, size_t length, size_t size) { return offset <= size && length <= size - offset; }
bool PowerOfTwo(DWORD n) { return n && !(n & (n - 1)); }
template<class T> T Read(const BYTE* data, size_t size, size_t offset) {
    Require(Range(offset, sizeof(T), size), "truncated header");
    T result; std::memcpy(&result, data + offset, sizeof(T)); return result;
}
template<class Optional> void Repair(BYTE* data, size_t size, size_t ntOffset, const IMAGE_FILE_HEADER& file, ULONGLONG base) {
    size_t optionalOffset = ntOffset + sizeof(DWORD) + sizeof(file);
    Require(file.SizeOfOptionalHeader >= sizeof(Optional), "optional header too small");
    auto optional = Read<Optional>(data, size, optionalOffset);
    Require(optional.SizeOfImage <= size && optional.SizeOfImage >= optional.SizeOfHeaders, "SizeOfImage out of range");
    Require(PowerOfTwo(optional.FileAlignment) && PowerOfTwo(optional.SectionAlignment) &&
        optional.FileAlignment <= optional.SectionAlignment, "invalid alignment");
    Require((optional.SectionAlignment < 4096 && optional.FileAlignment == optional.SectionAlignment) ||
        (optional.FileAlignment >= 512 && optional.FileAlignment <= 65536), "unsupported file alignment");
    Require(optional.NumberOfRvaAndSizes <= IMAGE_NUMBEROF_DIRECTORY_ENTRIES, "too many data directories");
    size_t sectionOffset = optionalOffset + file.SizeOfOptionalHeader;
    Require(file.NumberOfSections > 0 && file.NumberOfSections <= 96, "invalid section count");
    Require(Range(sectionOffset, file.NumberOfSections * sizeof(IMAGE_SECTION_HEADER), optional.SizeOfHeaders) &&
        optional.SizeOfHeaders % optional.FileAlignment == 0, "section table exceeds headers");
    std::vector<IMAGE_SECTION_HEADER> sections(file.NumberOfSections);
    std::memcpy(sections.data(), data + sectionOffset, sections.size() * sizeof(sections[0]));
    ULONGLONG previousEnd = optional.SizeOfHeaders;
    for (auto& section : sections) {
        ULONGLONG length = std::max(section.Misc.VirtualSize, section.SizeOfRawData);
        length = (length + optional.FileAlignment - 1) & ~(static_cast<ULONGLONG>(optional.FileAlignment) - 1);
        Require(section.VirtualAddress % optional.SectionAlignment == 0 && section.VirtualAddress >= previousEnd,
            "overlapping or unaligned sections");
        Require(length <= MAXDWORD && Range(section.VirtualAddress, static_cast<size_t>(length), optional.SizeOfImage), "section exceeds image");
        section.PointerToRawData = length ? section.VirtualAddress : 0;
        section.SizeOfRawData = static_cast<DWORD>(length);
        previousEnd = section.VirtualAddress + length;
    }
    std::vector<IMAGE_DEBUG_DIRECTORY> debug;
    DWORD debugRva = 0;
    if (optional.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_DEBUG) {
        auto directory = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
        if (directory.Size || directory.VirtualAddress) {
            Require(directory.VirtualAddress >= optional.SizeOfHeaders && directory.Size &&
                directory.Size % sizeof(IMAGE_DEBUG_DIRECTORY) == 0 &&
                Range(directory.VirtualAddress, directory.Size, optional.SizeOfImage), "debug directory out of range");
            debugRva = directory.VirtualAddress;
            debug.resize(directory.Size / sizeof(IMAGE_DEBUG_DIRECTORY));
            std::memcpy(debug.data(), data + debugRva, directory.Size);
            for (auto& entry : debug) {
                // Overlay-only debug payloads are not present in a memory dump.
                if (!entry.AddressOfRawData) { entry.PointerToRawData = entry.SizeOfData = 0; continue; }
                Require(Range(entry.AddressOfRawData, entry.SizeOfData, optional.SizeOfImage), "debug payload out of range");
                entry.PointerToRawData = entry.AddressOfRawData;
            }
        }
    }
    if (base) {
        Require(sizeof(optional.ImageBase) == 8 || base <= MAXDWORD, "PE32 base exceeds 32 bits");
        optional.ImageBase = static_cast<decltype(optional.ImageBase)>(base);
    }
    optional.CheckSum = 0;
    if (optional.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_SECURITY) optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY] = {};
    if (optional.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT) optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT] = {};
    // Commit only after complete validation; a failed repair leaves its input unchanged.
    std::memcpy(data + optionalOffset, &optional, sizeof(optional));
    std::memcpy(data + sectionOffset, sections.data(), sections.size() * sizeof(sections[0]));
    if (!debug.empty()) std::memcpy(data + debugRva, debug.data(), debug.size() * sizeof(debug[0]));
}
}
void RepairPe(BYTE* data, size_t size, ULONGLONG loadedBase) {
    Require(data != nullptr && size <= KD_MAX_IMAGE, "invalid image buffer");
    auto dos = Read<IMAGE_DOS_HEADER>(data, size, 0);
    Require(dos.e_magic == IMAGE_DOS_SIGNATURE && dos.e_lfanew >= sizeof(dos), "DOS header");
    size_t nt = static_cast<size_t>(dos.e_lfanew);
    Require(Read<DWORD>(data, size, nt) == IMAGE_NT_SIGNATURE, "NT signature");
    auto file = Read<IMAGE_FILE_HEADER>(data, size, nt + sizeof(DWORD));
    auto magic = Read<WORD>(data, size, nt + sizeof(DWORD) + sizeof(file));
    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) Repair<IMAGE_OPTIONAL_HEADER64>(data, size, nt, file, loadedBase);
    else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) Repair<IMAGE_OPTIONAL_HEADER32>(data, size, nt, file, loadedBase);
    else Require(false, "optional header magic");
}
void RepairFile(const fs::path& path, ULONGLONG loadedBase) {
    Handle file(CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr));
    if (!file) WinError("Open dump for PE repair");
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file.get(), &size)) WinError("Get dump size");
    if (size.QuadPart <= 0 || size.QuadPart > KD_MAX_IMAGE) throw std::runtime_error("Dump size must be between 1 byte and 1 GiB");
    Handle mapping(CreateFileMappingW(file.get(), nullptr, PAGE_READWRITE, 0, 0, nullptr));
    if (!mapping) WinError("Create PE mapping");
    auto data = static_cast<BYTE*>(MapViewOfFile(mapping.get(), FILE_MAP_WRITE, 0, 0, 0));
    if (!data) WinError("Map PE image");
    try {
        RepairPe(data, static_cast<size_t>(size.QuadPart), loadedBase);
        if (!FlushViewOfFile(data, 0)) WinError("Flush PE view");
    } catch (...) { UnmapViewOfFile(data); throw; }
    UnmapViewOfFile(data);
    if (!FlushFileBuffers(file.get())) WinError("Flush PE file");
}
OutputFile::OutputFile(const fs::path& destination, bool force) : destination_(fs::absolute(destination)), force_(force) {
    if (!force && fs::exists(destination_)) throw std::runtime_error("Output exists; use --force to replace it");
    fs::create_directories(destination_.parent_path());
    for (unsigned i = 0; i != 100; ++i) {
        temporary_ = destination_;
        temporary_ += L".partial." + std::to_wstring(GetCurrentProcessId()) + L"." + std::to_wstring(i);
        file_.reset(CreateFileW(temporary_.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
        if (file_) return;
        if (GetLastError() != ERROR_FILE_EXISTS) WinError("Create temporary output");
    }
    throw std::runtime_error("Could not create a unique temporary output");
}
OutputFile::~OutputFile() { file_.reset(); if (!temporary_.empty()) DeleteFileW(temporary_.c_str()); }
void OutputFile::Write(const BYTE* bytes, DWORD size) {
    DWORD total = 0;
    while (total < size) {
        DWORD written = 0;
        if (!WriteFile(file_.get(), bytes + total, size - total, &written, nullptr)) WinError("Write dump");
        if (!written) throw std::runtime_error("Zero-length file write");
        total += written;
    }
}
void OutputFile::Close() {
    if (file_ && !FlushFileBuffers(file_.get())) WinError("Flush dump");
    file_.reset();
}
void OutputFile::Commit() {
    Close();
    CheckCancelled();
    if (!MoveFileExW(temporary_.c_str(), destination_.c_str(), MOVEFILE_WRITE_THROUGH | (force_ ? MOVEFILE_REPLACE_EXISTING : 0))) WinError("Publish output");
    temporary_.clear();
}
void FixFile(const fs::path& input, const fs::path& output, bool force) {
    Handle source(CreateFileW(input.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
    if (!source) WinError("Open input image");
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(source.get(), &size)) WinError("Get input size");
    if (size.QuadPart <= 0 || size.QuadPart > KD_MAX_IMAGE) throw std::runtime_error("Input size must be between 1 byte and 1 GiB");
    OutputFile result(output, force);
    std::vector<BYTE> chunk(KD_MAX_CHUNK);
    LONGLONG remaining = size.QuadPart;
    while (remaining) {
        CheckCancelled();
        DWORD read = 0;
        if (!ReadFile(source.get(), chunk.data(), static_cast<DWORD>(std::min<LONGLONG>(remaining, chunk.size())), &read, nullptr)) WinError("Read input image");
        if (!read) throw std::runtime_error("Input image was truncated");
        result.Write(chunk.data(), read); remaining -= read;
    }
    source.reset(); result.Close();
    RepairFile(result.Temporary());
    result.Commit();
}
}
