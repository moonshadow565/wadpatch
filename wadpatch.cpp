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
#include <memory>

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

// shellcode for verify function
static uint8_t const shellcode[16] = {
    0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
    0xC3,                         // rtn
    0xCC, 0xCC,                   // nop
    0xCC, 0xCC, 0xCC, 0xCC,       // nop
    0xCC, 0xCC, 0xCC, 0xCC,       // nop
};

//68 ? ? ? ? 6A 04 6A 12 8D 44 24 ? 68 ? ? ? ? 50 E8 ? ? ? ? 83 C4 14 85 C0
static auto const pattern = std::regex {
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

static char const * const classnames[] = {
    "League of Legends (TM) Client",
    // TODO: do chinese, jp, KR clients have english class names as well ?
};

BOOL CALLBACK findwindow(HWND hwnd, LPARAM lParam) {
    char exename[256] = {0};
    if(GetWindowTextA(hwnd, exename, sizeof(exename) - 1)) {
        for(auto const& target: classnames){
            if(!strcmp(exename, target)) {
                DWORD pid = 0;
                if(GetWindowThreadProcessId(hwnd, &pid)){
                    *reinterpret_cast<DWORD*>(lParam) = pid;
                    return FALSE;
                };
            }
        }
    }
    return TRUE;
}


struct Process {
    HANDLE handle;
    uintptr_t base;
    uint8_t raw[0x1000] = {0};
    PIMAGE_SECTION_HEADER sbegin = nullptr;
    PIMAGE_SECTION_HEADER send = nullptr;
    uint32_t checksum = 1;


    Process(const Process&) = delete;
    Process(Process&&) = delete;
    Process& operator=(const Process&) = delete;
    Process& operator=(Process&&) = delete;

    Process(HANDLE h, uint32_t b)
        : handle(h), base(b)
    {
        if(handle == nullptr || handle == INVALID_HANDLE_VALUE) {
            return;
        }
        if(!ReadProcessMemory(
                    handle,
                    reinterpret_cast<LPVOID>(base),
                    raw,
                    sizeof(raw),
                    nullptr)) {
            return;
        }
        auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(raw);
        auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(raw + dos->e_lfanew);
        sbegin = IMAGE_FIRST_SECTION(nt);
        send = sbegin + nt->FileHeader.NumberOfSections;
        checksum = static_cast<uint32_t>(nt->OptionalHeader.CheckSum);
    }

    ~Process()
    {
        if(!handle && handle != INVALID_HANDLE_VALUE) {
            CloseHandle(handle);
        }
    }

    static std::unique_ptr<Process>
    Create(DWORD pid, char const * const what) {
        auto process = OpenProcess(
                    PROCESS_VM_OPERATION
                    | PROCESS_VM_READ
                    | PROCESS_VM_WRITE
                    | PROCESS_QUERY_INFORMATION,
                    false,
                    pid);
        if(!process || process == INVALID_HANDLE_VALUE) {
            puts("Failed to create process handle!");
            return nullptr;
        }
        HMODULE mods[1024];
        DWORD bmsize;
        if (!EnumProcessModules(process, mods, sizeof(mods), &bmsize))
        {
            puts("Failed to enumerate process modules!");
            CloseHandle(process);
            return nullptr;
        }
        auto const mend = mods + (bmsize / sizeof(HMODULE));
        for (auto m = mods; m < mend; m++)
        {
            char name[MAX_PATH];
            if (GetModuleFileNameExA(process, *m, name, sizeof(name)))
            {
                if(strstr(name, what) != nullptr) {
                    return std::make_unique<Process>(
                        process, reinterpret_cast<uintptr_t>(*m));
                }
            }
        }
        puts("No League of Legends.exe module found!");
        CloseHandle(process);
        return nullptr;
    }

    uint32_t ScanOffset() const {
        PIMAGE_SECTION_HEADER section = nullptr;
        for(auto s = this->sbegin; s < this->send; s++) {
            auto const name = reinterpret_cast<char const*>(s->Name);
            if(!strcmp(name, ".text")) {
                section = s;
                break;
            }
        }
        if(!section) {
            puts("Did not find .text section!");
            return 0;
        }
        auto const pbegin = this->base + section->VirtualAddress;
        auto const psize = pbegin + section->SizeOfRawData;
        std::string pbuffer(size_t{psize}, '\0');
        for(size_t p = 0; p < psize; p+= 0x1000) {
            ReadProcessMemory(
                        this->handle,
                        reinterpret_cast<void*>(pbegin + p),
                        &pbuffer[p],
                        0x1000,
                        nullptr);
        }
        if(std::smatch match; std::regex_search(pbuffer, match, pattern)) {
            auto const target_cpy = match[1].str();
            auto const target_raw = &target_cpy[0];
            auto const result = *reinterpret_cast<uint32_t const*>(target_raw);
            return result - this->base;
        }
        puts("Failed to find offset!");
        return 0;
    }

    int Patch(uint32_t offset) const {
        uint32_t vtable_ptr = {};
        if(!ReadProcessMemory(this->handle,
                              reinterpret_cast<void*>(this->base + offset),
                              &vtable_ptr,
                              sizeof(vtable_ptr),
                              nullptr
                              )){
            puts("Failed to read vtable_ptr!");
            return false;
        }

        EVP_PKEY_METHOD vtable = {};
        if(!ReadProcessMemory(this->handle,
                              reinterpret_cast<void*>(vtable_ptr),
                              reinterpret_cast<void*>(&vtable),
                              sizeof(vtable),
                              nullptr
                              )){
            puts("Failed to read vtable!");
            return false;
        }

        auto remotefn = VirtualAllocEx(this->handle,
                                       nullptr,
                                       sizeof(vtable),
                                       MEM_RESERVE | MEM_COMMIT,
                                       PAGE_READWRITE);
        if(!remotefn) {
            puts("Failed to allocate remote function!");
            return false;
        }

        if(!WriteProcessMemory(this->handle,
                               remotefn,
                               &shellcode,
                               sizeof(shellcode),
                               nullptr)) {
            puts("Failed to write remote function!");
            return false;
        }

        if(DWORD old; !VirtualProtectEx(
                    this->handle,
                    remotefn,
                    sizeof(shellcode),
                    PAGE_EXECUTE, &old)){
            puts("Failed to mark executable remote function!");
            return false;
        }

        vtable.verify = reinterpret_cast<uint32_t>(remotefn);
        auto remotevtable = VirtualAllocEx(this->handle,
                                           nullptr,
                                           sizeof(vtable),
                                           MEM_RESERVE | MEM_COMMIT,
                                           PAGE_READWRITE);
        if(!remotevtable) {
            puts("Failed to allocate remote vtable!");
            return false;
        }

        if(!WriteProcessMemory(this->handle,
                               remotevtable,
                               reinterpret_cast<void*>(&vtable),
                               sizeof(vtable),
                               nullptr)) {
            puts("Failed to write remote vtable!");
            return false;
        }

        if(!WriteProcessMemory(this->handle,
                           reinterpret_cast<void*>(offset + this->base),
                           reinterpret_cast<void*>(&remotevtable),
                           sizeof(remotevtable),
                           nullptr)) {
            puts("Failed to patch offset!");
            return false;
        }
        return true;
    }
};


int main() {
    uint32_t offset = 0;
    uint32_t checksum = 0;
    if(FILE* file = nullptr; !fopen_s(&file,"wadpatch.txt","r") && file) {
        fscanf_s(file, "0x%08X 0x%08X\n", &offset, &checksum);
        fclose(file);
    }
    for(;;) {
        puts("=============================================");
        printf("Offset: 0x%08X, Checksum: 0x%08X\n", offset, checksum);
        printf("Press enter to continue...");
        getc(stdin);
        puts("Scanning...");
        DWORD pid = 0;
        for(; !pid ; EnumWindows(findwindow, reinterpret_cast<LPARAM>(&pid))) {
            Sleep(50);
        };
        auto const process = Process::Create(pid, "League of Legends.exe");
        if(!process) {
            continue;
        }
        if(!offset || process->checksum != checksum) {
            checksum = process->checksum;
            offset = process->ScanOffset();
            puts("Rescanned!");
        }
        if(!offset || !process->Patch(offset)) {
            continue;
        }
        if(FILE* file = nullptr; !fopen_s(&file, "wadpatch.txt","w") && file) {
            fprintf_s(file, "0x%08X 0x%08X\n", offset, checksum);
            fclose(file);
        }
        puts("Patched!");
    }
}
