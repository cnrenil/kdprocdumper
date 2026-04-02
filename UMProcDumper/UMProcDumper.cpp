#include <iostream>
#include <cstring>
#include <string>
#include <Windows.h>
#include <Shlwapi.h>

#pragma comment(lib, "Shlwapi.lib")

#define IOCTL_MYDEVICE_DUMP CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_MYDEVICE_IMAGESIZE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define PROC_DUMPER_MAX_MODULE_NAME 260

#define ADJUST_OPTONAL_HEADER true
#define MINIMAL_DIRECTORY_ENTRIES false

typedef struct _INPUT_DUMP_INFO
{
	ULONG ProcessId;
	CHAR ModuleName[PROC_DUMPER_MAX_MODULE_NAME];
} INPUT_DUMP_INFO, * PINPUT_DUMP_INFO;

static std::string SanitizePathComponent(const char* value)
{
	std::string sanitized = value != nullptr ? value : "unknown";
	for (char& ch : sanitized)
	{
		switch (ch)
		{
		case '<':
		case '>':
		case ':':
		case '"':
		case '/':
		case '\\':
		case '|':
		case '?':
		case '*':
			ch = '_';
			break;
		default:
			break;
		}
	}

	if (sanitized.empty())
	{
		sanitized = "unknown";
	}

	return sanitized;
}

static std::string GetProcessName(DWORD processId)
{
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
	if (hProcess == NULL)
	{
		return std::string("pid_") + std::to_string(processId);
	}

	char processPath[MAX_PATH] = {};
	DWORD processPathSize = MAX_PATH;
	if (!QueryFullProcessImageNameA(hProcess, 0, processPath, &processPathSize))
	{
		CloseHandle(hProcess);
		return std::string("pid_") + std::to_string(processId);
	}

	CloseHandle(hProcess);
	char processName[MAX_PATH] = {};
	strcpy_s(processName, PathFindFileNameA(processPath));
	PathRemoveExtensionA(processName);
	return SanitizePathComponent(processName);
}

static std::string GetDefaultOutputPath(DWORD processId, const char* moduleName)
{
	char exePath[MAX_PATH] = {};
	DWORD length = GetModuleFileNameA(NULL, exePath, MAX_PATH);
	if (length == 0 || length >= MAX_PATH)
	{
		return SanitizePathComponent(moduleName) + ".bin";
	}

	std::string outputPath(exePath);
	size_t separatorPos = outputPath.find_last_of("\\/");
	if (separatorPos == std::string::npos)
	{
		outputPath.clear();
	}
	else
	{
		outputPath.resize(separatorPos + 1);
	}

	std::string processName = GetProcessName(processId);
	std::string sanitizedModuleName = SanitizePathComponent(moduleName);
	std::string outputRoot = outputPath + "Output";
	CreateDirectoryA(outputRoot.c_str(), NULL);

	std::string processDirectory = outputRoot + "\\" + processName;
	CreateDirectoryA(processDirectory.c_str(), NULL);

	outputPath = processDirectory + "\\";
	outputPath += sanitizedModuleName;
	outputPath += ".bin";
	return outputPath;
}

int main(int argc, char* argv[])
{
	if (argc > 1 && std::string(argv[1]) == "--list") {
		// TODO: List all modules inside a process
		return 0;
	}

	// Open the device
	HANDLE hDevice = CreateFile(L"\\\\.\\ProcDumper", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (hDevice == INVALID_HANDLE_VALUE)
	{
		printf("CreateFile failed! (%d)\n", GetLastError());
		return 1;
	}

	// Get the process id
	DWORD processId;
	printf("Enter the process id: ");
	scanf("%d", &processId);

	// Get the module name
	CHAR moduleName[PROC_DUMPER_MAX_MODULE_NAME] = {};
	printf("Enter the module name: ");
	if (scanf_s("%259s", moduleName, (unsigned)_countof(moduleName)) != 1)
	{
		printf("Failed to read the module name.\n");
		CloseHandle(hDevice);
		return 1;
	}

	// Initialize the structure to pass to the driver
	INPUT_DUMP_INFO inputDumpInfo;
	ZeroMemory(&inputDumpInfo, sizeof(inputDumpInfo));
	inputDumpInfo.ProcessId = processId;
	strcpy_s(inputDumpInfo.ModuleName, moduleName);

	// Send the IOCTL to get the image size
	ULONG imageSize;
	DWORD bytesReturned;
	if (!DeviceIoControl(hDevice, IOCTL_MYDEVICE_IMAGESIZE, &inputDumpInfo, sizeof(inputDumpInfo), &imageSize,
		sizeof(imageSize), &bytesReturned, NULL))
	{
		printf("DeviceIoControl failed! (%d)\n", GetLastError());
		CloseHandle(hDevice);
		return 1;
	}

	// Allocate memory to store the image
	CHAR* image = (CHAR*)malloc(imageSize);
	if (image == nullptr)
	{
		printf("Failed to allocate %lu bytes for the dumped image.\n", imageSize);
		CloseHandle(hDevice);
		return 1;
	}

	// Send the IOCTL to dump the process
	if (!DeviceIoControl(hDevice, IOCTL_MYDEVICE_DUMP, &inputDumpInfo, sizeof(inputDumpInfo), image,
		imageSize, &bytesReturned, NULL))
	{
		printf("DeviceIoControl failed! (%d)\n", GetLastError());
		free(image);
		CloseHandle(hDevice);
		return 1;
	}

	std::string outputPath = GetDefaultOutputPath(processId, moduleName);

	// Save to file
	FILE* file = nullptr;
	errno_t openError = fopen_s(&file, outputPath.c_str(), "wb");
	if (openError != 0 || file == nullptr)
	{
		printf("Failed to open output file '%s' for writing. errno=%d\n", outputPath.c_str(), openError);
		free(image);
		CloseHandle(hDevice);
		return 1;
	}

	if (fwrite(image, 1, imageSize, file) != imageSize)
	{
		printf("Failed to write dumped image to '%s'.\n", outputPath.c_str());
		fclose(file);
		free(image);
		CloseHandle(hDevice);
		return 1;
	}

	fclose(file);

	// Free the memory
	free(image);


	// Close the device
	CloseHandle(hDevice);

	// Open the file
	HANDLE hFile = CreateFileA(outputPath.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		std::cout << "CreateFile failed for '" << outputPath << "' (" << GetLastError() << ")" << std::endl;
		return 1;
	}

	// Read file as buffer
	DWORD fileSize = GetFileSize(hFile, NULL);
	BYTE* buffer = new BYTE[fileSize];
	DWORD bytesRead;
	if (!ReadFile(hFile, buffer, fileSize, &bytesRead, NULL)) {
		std::cout << "ReadFile failed! (" << GetLastError() << ")" << std::endl;
		delete[] buffer;
		CloseHandle(hFile);
		return 1;
	}

	// Fix the PE header
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)buffer;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(buffer + dosHeader->e_lfanew);

	// Get section header
	PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeader);

	// Fix sections
	for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
		// Fix raw address
		sectionHeader[i].PointerToRawData = sectionHeader[i].VirtualAddress;
		// Fix raw size
		sectionHeader[i].SizeOfRawData = sectionHeader[i].Misc.VirtualSize;
	}

	if (ADJUST_OPTONAL_HEADER)
	{
		// Adjust other optional header values
		// ntHeader->OptionalHeader.SizeOfImage = sectionHeader[ntHeader->FileHeader.NumberOfSections - 1].VirtualAddress + sectionHeader[ntHeader->FileHeader.NumberOfSections - 1].Misc.VirtualSize;
		ntHeader->OptionalHeader.SizeOfHeaders = sectionHeader[0].PointerToRawData;

		if (MINIMAL_DIRECTORY_ENTRIES)
		{
			// Adjust data directory values
			ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = 0;
			ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = 0;
			ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = 0;
			ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size = 0;
			ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = 0;
			ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size = 0;

			// Adjust import address table
			ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = 0;
			ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size = 0;

			// Adjust bound import table
			ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = 0;
			ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = 0;
		}
		else {
			// Read debug directory
			PIMAGE_DEBUG_DIRECTORY debugDirectory = (PIMAGE_DEBUG_DIRECTORY)(buffer + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress);

			// Set the pointer to raw data equal to the virtual address
			debugDirectory->PointerToRawData = debugDirectory->AddressOfRawData;
		}
	}

	// Write the buffer to the file
	SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
	if (!WriteFile(hFile, buffer, fileSize, &bytesRead, NULL)) {
		std::cout << "WriteFile failed! (" << GetLastError() << ")" << std::endl;
		delete[] buffer;
		CloseHandle(hFile);
		return 1;
	}

	// Cleanup
	delete[] buffer;

	CloseHandle(hFile);
	std::cout << "Dump written to: " << outputPath << std::endl;

	return 0;
}

