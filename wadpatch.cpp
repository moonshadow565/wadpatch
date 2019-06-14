#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <cinttypes>
#include <cstdio>

/*
Signature:
68 ? ? ? ?          ; push    offset method_compare
6A 04               ; push    4
6A 12               ; push    12h
8D 44 24 1C         ; lea     eax, [esp+0x1C]
68 ? ? ? ?          ; push    offset pkey_methods
50                  ; push    eax
E8 ? ? ? ?          ; call    OBJ_bsearch_
83 C4 14            ; add     esp, 14h
85 C0               ; test    eax, eax

68 ? ? ? ? 6A 04 6A 12 8D 44 24 ? 68 ? ? ? ? 50 E8 ? ? ? ? 83 C4 14 85 C0
*/

// OpenSSL 1.1.1b definitions
extern "C" {
    typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;
    typedef struct evp_pkey_method_st EVP_PKEY_METHOD;
    typedef struct evp_pkey_st EVP_PKEY;
    typedef struct evp_md_ctx_st EVP_MD_CTX;

    typedef struct evp_pkey_method_st {
        int pkey_id;
        int flags;
        int (*init) (EVP_PKEY_CTX *ctx);
        int (*copy) (EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src);
        void (*cleanup) (EVP_PKEY_CTX *ctx);
        int (*paramgen_init) (EVP_PKEY_CTX *ctx);
        int (*paramgen) (EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);
        int (*keygen_init) (EVP_PKEY_CTX *ctx);
        int (*keygen) (EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);
        int (*sign_init) (EVP_PKEY_CTX *ctx);
        int (*sign) (EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                     const unsigned char *tbs, size_t tbslen);
        int (*verify_init) (EVP_PKEY_CTX *ctx);
        int (*verify) (EVP_PKEY_CTX *ctx,
                       const unsigned char *sig, size_t siglen,
                       const unsigned char *tbs, size_t tbslen);
        int (*verify_recover_init) (EVP_PKEY_CTX *ctx);
        int (*verify_recover) (EVP_PKEY_CTX *ctx,
                               unsigned char *rout, size_t *routlen,
                               const unsigned char *sig, size_t siglen);
        int (*signctx_init) (EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx);
        int (*signctx) (EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                        EVP_MD_CTX *mctx);
        int (*verifyctx_init) (EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx);
        int (*verifyctx) (EVP_PKEY_CTX *ctx, const unsigned char *sig, int siglen,
                          EVP_MD_CTX *mctx);
        int (*encrypt_init) (EVP_PKEY_CTX *ctx);
        int (*encrypt) (EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
                        const unsigned char *in, size_t inlen);
        int (*decrypt_init) (EVP_PKEY_CTX *ctx);
        int (*decrypt) (EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
                        const unsigned char *in, size_t inlen);
        int (*derive_init) (EVP_PKEY_CTX *ctx);
        int (*derive) (EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen);
        int (*ctrl) (EVP_PKEY_CTX *ctx, int type, int p1, void *p2);
        int (*ctrl_str) (EVP_PKEY_CTX *ctx, const char *type, const char *value);
        int (*digestsign) (EVP_MD_CTX *ctx, unsigned char *sig, size_t *siglen,
                           const unsigned char *tbs, size_t tbslen);
        int (*digestverify) (EVP_MD_CTX *ctx, const unsigned char *sig,
                             size_t siglen, const unsigned char *tbs,
                             size_t tbslen);
        int (*check) (EVP_PKEY *pkey);
        int (*public_check) (EVP_PKEY *pkey);
        int (*param_check) (EVP_PKEY *pkey);

        int (*digest_custom) (EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx);
    } EVP_PKEY_METHOD;

    static int pmeth_verify(EVP_PKEY_CTX *ctx,
                            const unsigned char *sig, size_t siglen,
                            const unsigned char *tbs, size_t tbslen) {
        ((void)ctx, (void)sig, (void)siglen, (void)tbs, (void)tbslen);
        return 1;
    }

    static EVP_PKEY_METHOD pmeth = {};

    __declspec(dllexport) void wadpatch(uint32_t offset) {
    #ifdef LOG_STUFF
            AllocConsole();
            freopen("CONOUT$", "w", stdout);
    #endif
        if(FILE* file = nullptr; !fopen_s(&file, "wadpatch.txt", "r") && file) {
            uint32_t offset_file = 0;
            if(fscanf_s(file, "0x%08X", &offset_file)) {
                offset = offset_file;
            }
            fclose(file);
        }
        if(!offset) {
            return;
        }
        auto const base = reinterpret_cast<DWORD>(GetModuleHandleA(nullptr));
        auto target = reinterpret_cast<EVP_PKEY_METHOD const**>(base + offset);
        if(!*target || (*target)->pkey_id != 6) {
            return;
        }
        pmeth = **target;
        pmeth.verify = &pmeth_verify;
        *target = &pmeth;
    }
}

BOOL WINAPI DllMain(HINSTANCE,DWORD fdwReason, LPVOID) {
	if (fdwReason == DLL_PROCESS_ATTACH) {
        wadpatch(0);
	}
	return TRUE;
}
