#pragma once
#include "common.h"
namespace kd {
// Input is an RVA-layout memory image. Validate everything before changing bytes.
void RepairPe(BYTE* data, size_t size, ULONGLONG loadedBase = 0);
void RepairFile(const fs::path& path, ULONGLONG loadedBase = 0);
class OutputFile {
    fs::path temporary_;
    fs::path destination_;
    Handle file_;
    bool force_;
public:
    OutputFile(const fs::path& destination, bool force);
    ~OutputFile();
    void Write(const BYTE* bytes, DWORD size);
    void Close();
    const fs::path& Temporary() const { return temporary_; }
    void Commit();
};
void FixFile(const fs::path& input, const fs::path& output, bool force);
}
