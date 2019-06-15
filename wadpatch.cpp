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

struct EVP_PKEY_METHOD {
    uint32_t pkey_id;
    uint32_t flags;
    uint32_t init;
    uint32_t copy;
    uint32_t cleanup;
    uint32_t paramgen_init;
    uint32_t paramgen;
    uint32_t keygen_init;
    uint32_t keygen;
    uint32_t sign_init;
    uint32_t sign;
    uint32_t verify_init;
    uint32_t verify;
    uint32_t verify_recover_init;
    uint32_t verify_recover;
    uint32_t signctx_init;
    uint32_t signctx;
    uint32_t verifyctx_init;
    uint32_t verifyctx;
    uint32_t encrypt_init;
    uint32_t encrypt;
    uint32_t decrypt_init;
    uint32_t decrypt;
    uint32_t derive_init;
    uint32_t derive;
    uint32_t ctrl;
    uint32_t ctrl_str;
    uint32_t digestsign;
    uint32_t digestverify;
    uint32_t check;
    uint32_t public_check;
    uint32_t param_check;
    uint32_t digest_custom;
};

static uint32_t SigScan(const char* const buffer, size_t size) {
    //68 ? ? ? ? 6A 04 6A 12 8D 44 24 ? 68 ? ? ? ? 50 E8 ? ? ? ? 83 C4 14 85 C0
    auto const pattern = std::regex {
        "\\x68...."             // push    offset method_compare
        "\\x6A\\x04"            // push    4
        "\\x6A\\x12"            // push    12h
        "\\x8D\\x44\\x24."      // lea     eax, [esp+0x1C]
        "\\x68(....)"           // push    offset pkey_methods
        "\\x50"                 // push    eax
        "\\xE8...."             // call    OBJ_bsearch_
        "\\x83\\xC4\\x14"       // add     esp, 14h
        "\\x85\\xC0"            // test    eax, eax
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
                    PROCESS_VM_OPERATION
                    | PROCESS_VM_READ
                    | PROCESS_VM_WRITE
                    | PROCESS_QUERY_INFORMATION,
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
    PIMAGE_SECTION_HEADER sbegin = nullptr;
    PIMAGE_SECTION_HEADER send = nullptr;
    explicit operator bool() const {
        return dos != nullptr && nt != nullptr;
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
    result.sbegin = IMAGE_FIRST_SECTION(result.nt);
    result.send = result.sbegin + result.nt->FileHeader.NumberOfSections;
    return result;
}

static uint32_t GetOffset(Process const& process, PEHeader const& pe) {
    auto const section = std::find_if(pe.sbegin, pe.send, [](auto section){
       auto const name = reinterpret_cast<char const*>(section.Name);
       if(std::string_view{name} == ".text") {
           return true;
       }
       return false;
    });
    if(section == pe.send && !section) {
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

static int Patch(Process const& process, uint32_t offset) {
    uint32_t vtable_ptr = {};
    if(!ReadProcessMemory(process.handle,
                          reinterpret_cast<void*>(process.base + offset),
                          &vtable_ptr,
                          sizeof(vtable_ptr),
                          nullptr
                          )){
        return false;
    }
    printf("vtable ptr: 0x%08X\n", vtable_ptr);
    EVP_PKEY_METHOD vtable = {};
    if(!ReadProcessMemory(process.handle,
                          reinterpret_cast<void*>(vtable_ptr),
                          reinterpret_cast<void*>(&vtable),
                          sizeof(vtable),
                          nullptr
                          )){
        return false;
    }

    auto remotefn = VirtualAllocEx(process.handle,
                                   nullptr,
                                   sizeof(vtable),
                                   MEM_RESERVE | MEM_COMMIT,
                                   PAGE_READWRITE);
    if(!remotefn) {
        return false;
    }
    uint8_t shellcode[16] = {
        0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
        0xC3,                         // rtn
        0xCC, 0xCC,                   // nop
        0xCC, 0xCC, 0xCC, 0xCC,       // nop
        0xCC, 0xCC, 0xCC, 0xCC,       // nop
    };
    if(!WriteProcessMemory(process.handle,
                           remotefn,
                           &shellcode,
                           sizeof(shellcode),
                           nullptr)) {
        return false;
    }
    if(DWORD old; !VirtualProtectEx(
                process.handle,
                remotefn,
                sizeof(shellcode),
                PAGE_EXECUTE, &old)){
        return false;
    }

    vtable.verify = reinterpret_cast<uint32_t>(remotefn);
    auto remotevtable = VirtualAllocEx(process.handle,
                                       nullptr,
                                       sizeof(vtable),
                                       MEM_RESERVE | MEM_COMMIT,
                                       PAGE_READWRITE);
    if(!remotevtable) {
        return false;
    }
    if(!WriteProcessMemory(process.handle,
                           remotevtable,
                           reinterpret_cast<void*>(&vtable),
                           sizeof(vtable),
                           nullptr)) {
        return false;
    }

    if(!WriteProcessMemory(process.handle,
                       reinterpret_cast<void*>(offset + process.base),
                       reinterpret_cast<void*>(&remotevtable),
                       sizeof(remotevtable),
                       nullptr)) {
        return false;
    }
    return true;
}

static void DoPatch(uint32_t offset) {
    printf("Scanning for process...\n");
    for(;;) {
        auto const process = GetProcess("League of Legends.exe");
        if(!process) {
            Sleep(50);
            continue;
        }
        auto const pe = GetPEHeader(process);
        if(!pe) {
            printf("Failed to read PEHeader!\n");
            break;
        }
        if(!Patch(process, offset)) {
            printf("Failed to patch!\n");
        }
        printf("Patched!\n");
        break;
    }
}

static uint32_t DoScan(uint32_t msdelay = 1000) {
    printf("Scanning for process...\n");
    for(;;) {
        auto const process = GetProcess("League of Legends.exe");
        if(!process) {
            Sleep(100);
            continue;
        }
        printf("Base: %08X\n", process.base);
        auto const pe = GetPEHeader(process);
        if(!pe) {
            printf("Failed to read PEHeader!\n");
            return 0;
        }
        printf("Scanning process memory...\n");
        Sleep(msdelay);
        auto offset = GetOffset(process, pe);
        printf("Offset: 0x%08X\n", offset);
        if(FILE* file = nullptr; !fopen_s(&file,"wadpatch.txt","w") && file) {
            fprintf_s(file, "0x%08X\n", offset);
            fclose(file);
        }
        return offset;
    }
}

int main() {
    uint32_t offset = 0;
    uint32_t msdelay = 1000;
    if(FILE* file = nullptr; !fopen_s(&file,"wadpatch.txt","r") && file) {
        fscanf_s(file, "0x%08X\n", &offset);
        fclose(file);
    }
    printf("Offset: 0x%08X\n", offset);
    for(;;) {
        printf("Options:\n"
               "0) Quit\n"
               "1) Scan for offset\n"
               "2) Wait for the game to start and patch\n"
               "3) Scan delay(if league launches too fast or too slow)\n"
               "> ");
        int choice = 0;
        while(!fscanf_s(stdin, "%d", &choice));
        switch(choice) {
        case 0:
            return 0;
        case 1:
            if(auto newoff = DoScan(); newoff) {
                offset = newoff;
            }
            break;
        case 2:
            if(offset) {
                DoPatch(offset);
            } else {
                printf("Can't patch without working offset.\n");
            }
            break;
        case 3:
            printf("sleep: ");
            fscanf_s(stdin, "%u", &msdelay);
            break;
        }
    }
}
