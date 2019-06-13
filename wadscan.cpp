#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <winnt.h>
#include <Psapi.h>
#include <cinttypes>
#include <cstring>
#include <cstdio>
#include <optional>
#include <vector>
#include <regex>
#include <algorithm>

static uint32_t SigScan(const char* const buffer, size_t size) {
    auto const pattern = std::regex {
        "\\xA1(....)"               // mov eax, malloc_impl
        "\\x56"                     // push esi
        "\\x57"                     // push edi
        "\\x85\\xC0"                // test eax, eax
        "\\x74\\x1B"                // jz short default_malloc
        "\\x3D(....)"                 // cmp eax, CRYPTO_malloc
        "\\x74\\x14"                // jz short default_malloc
        "\\xFF\\x74\\x24\\x14"      // push  [esp + 0xC + 8]
        "\\x8B\\x7C\\x24\\x10"      // mov edi, [esp + 0xC + 4]
        "\\xFF\\x74\\x24\\x14"      // push [esp + 0xC + 8]
        "\\x57"                     // push edi
        "\\xFF\\xD0"                // call eax
        "\\x83\\xC4\\x0C"           // add esp, 0xC
    };

    std::cmatch match;
    if(std::regex_search(buffer, buffer+size, match, pattern)) {
        auto const target_cpy = match[1].str();
        auto const target_raw = &target_cpy[0];
        return *reinterpret_cast<uint32_t const*>(target_raw);
    }
    return 0;
}

struct Process {
    HANDLE handle;
    uintptr_t base;
    Process(HANDLE h, uint32_t b)
        : handle(h), base(b)
    {}
    Process(nullptr_t)
        : handle(nullptr), base(0)
    {}
    ~Process()
    {
        if(handle) {
            CloseHandle(handle);
        }
    }
    Process(const Process&) = delete;
    Process(Process&& other)
        : handle(other.handle),
          base(other.base)
    {
        other.handle = nullptr;
        other.base = 0;
    }

    explicit operator bool() const {
        return handle != nullptr && base != 0;
    }
};

static Process GetProcess(char const * const what) {
    DWORD processes[1024], bpsize;
    if ( !EnumProcesses( processes, sizeof(processes), &bpsize) )
    {
        return nullptr;
    }
    auto const pend = processes + (bpsize / sizeof(DWORD));
    for(auto pid = processes; pid < pend; pid++) {
        auto process = OpenProcess(
                    PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                    false,
                    *pid);
        if(!process) {
            continue;
        }
        HMODULE mods[1024];
        DWORD bmsize;
        if (!EnumProcessModules(process, mods, sizeof(mods), &bmsize))
        {
            CloseHandle(process);
            continue;
        }
        auto const mend = mods + (bmsize / sizeof(HMODULE));
        for (auto m = mods; m < mend; m++)
        {
            char name[MAX_PATH];
            if (GetModuleFileNameExA(process, *m, name, sizeof(name)))
            {
                if(strstr(name, what) != nullptr) {
                    return {process, reinterpret_cast<uintptr_t>(*m)};
                }
            }
        }
        CloseHandle(process);
    }
    return nullptr;
}

struct PEHeader {
    uint8_t raw[0x1000] = {0};
    PIMAGE_DOS_HEADER dos = nullptr;
    PIMAGE_NT_HEADERS nt  = nullptr;

    struct SectionsRange{
        PIMAGE_SECTION_HEADER const pbegin;
        PIMAGE_SECTION_HEADER const pend;
        auto begin() const& { return pbegin; }
        auto end() const& { return pend; }

        auto cbegin() const& { return pbegin; }
        auto cend() const& { return pend; }

        inline IMAGE_SECTION_HEADER const*
        operator[](std::string_view what) const& {
            for(auto const& section : *this) {
                auto name = reinterpret_cast<char const*>(section.Name);
                if(what == std::string_view{name}) {
                    return &section;
                }
            }
            return nullptr;
        }
    };

    inline auto sections() const& {
        if(!dos) {
            return SectionsRange{nullptr, nullptr};
        }
        auto const pbegin = IMAGE_FIRST_SECTION(nt);
        auto const pend = pbegin + nt->FileHeader.NumberOfSections;
        return SectionsRange { pbegin, pend };
    }

    explicit operator bool() const {
        return dos != nullptr;
    }
};

static PEHeader GetPEHeader(Process const& process) {
    PEHeader result = {};
    if(!process) {
        return result;
    }
    if(!ReadProcessMemory(
                process.handle,
                reinterpret_cast<LPVOID>(process.base),
                result.raw,
                sizeof(result.raw),
                nullptr)) {
        return result;
    }
    result.dos = reinterpret_cast<PIMAGE_DOS_HEADER>(result.raw);
    result.nt = reinterpret_cast<PIMAGE_NT_HEADERS>(
                result.raw + result.dos->e_lfanew);
    return result;
}

static uint32_t GetOffset(Process const& process, PEHeader const& peheader) {
    auto const section = peheader.sections()[".text"];
    if(!section) {
        return 0;
    }
    auto const pbegin = process.base + section->VirtualAddress;
    auto const psize = pbegin + section->SizeOfRawData;
    std::string pbuffer(size_t{psize}, '\0');
    for(size_t p = 0; p < psize; p+= 0x1000) {
        ReadProcessMemory(
                    process.handle,
                    reinterpret_cast<void*>(pbegin + p),
                    &pbuffer[p],
                    0x1000,
                    nullptr);
    }
    if(auto const result = SigScan(&pbuffer[0], psize); result) {
        return result - process.base;
    }
    return 0;
}


int main(int argc, char** argv) {
    printf("Scanning for process...\n");
    for(;;) {
        auto const process = GetProcess("League of Legends.exe");
        if(!process) {
            Sleep(1000);
            continue;
        }
        printf("Waiting for process to load...\n");
        Sleep(1000);
        auto const peheader = GetPEHeader(process);
        if(!peheader) {
            printf("Failed to read PEHeader!\n");
            break;
        }
        printf("Scanning process memory...\n");
        auto offset = GetOffset(process, peheader);
        printf("Target: 0x%08X\n", offset);
        if(FILE* file = nullptr; !fopen_s(&file,"wadpatch.txt","w") && file) {
            fprintf_s(file, "0x%08X\n", offset);
            fclose(file);
        }
        break;
    }
    printf("Press enter to exit...\n");
    getc(stdin);
    return 0;
}
