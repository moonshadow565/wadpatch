#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <cstring>
#include <cstdlib>
#include <inttypes.h>

#ifdef LOG_STUFF
#include <cstdio>
#endif

// the line that OpenSSL reports allocation from
// for EVP_MD_CTX_new
#define MALLOC_LINE 51

// offset in league
#define MALLOC_IMPL_OFF (0x2470994 - 0xDE0000)

/* Todo sig scan:
A1 94 09 47 02  ; mov eax, malloc_impl
56              ; push esi
57              ; push edi
85 C0           ; test eax, eax
74 1B           ; jz short default_malloc
3D 10 91 90 01  ; cmp eax, CRYPTO_malloc
74 14           ; jz short default_malloc
FF 74 24 14     ; push  [esp + 0xC + 8]
8B 7C 24 10     ; mov edi, [esp + 0xC + 4]
FF 74 24 14     ; push [esp + 0xC + 8]
57              ; push edi
FF D0           ; call eax
83 C4 0C        ; add esp, 0xC
*/

// OpenSSL 1.1.1b definitions
extern "C" {
    using malloc_f = void*(*)(size_t num, const char *file, int line);
    static malloc_f malloc_org = nullptr;
    #define EVP_MD_CTX_FLAG_CLEANED         0x0002
    #define EVP_PKEY_FLAG_SIGCTX_CUSTOM     4
    #define EVP_MD_CTX_FLAG_FINALISE        0x0200
    typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;
    typedef struct evp_pkey_method_st EVP_PKEY_METHOD;
    typedef struct evp_pkey_st EVP_PKEY;
    typedef struct evp_md_ctx_st EVP_MD_CTX;
    typedef struct evp_md_st EVP_MD;
    typedef struct engine_st ENGINE;

    typedef int CRYPTO_REF_COUNT;
    typedef int EVP_PKEY_gen_cb(EVP_PKEY_CTX *ctx);

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

    typedef struct evp_pkey_ctx_st {
        /* Method associated with this operation */
        const EVP_PKEY_METHOD *pmeth;
        /* Engine that implements this method or NULL if builtin */
        ENGINE *engine;
        /* Key: may be NULL */
        EVP_PKEY *pkey;
        /* Peer key for key agreement, may be NULL */
        EVP_PKEY *peerkey;
        /* Actual operation */
        int operation;
        /* Algorithm specific data */
        void *data;
        /* Application specific data */
        void *app_data;
        /* Keygen callback */
        EVP_PKEY_gen_cb *pkey_gencb;
        /* implementation specific keygen data */
        int *keygen_info;
        int keygen_info_count;
    } EVP_PKEY_CTX;

    typedef struct evp_md_st {
        int type;
        int pkey_type;
        int md_size;
        unsigned long flags;
        int (*init) (EVP_MD_CTX *ctx);
        int (*update) (EVP_MD_CTX *ctx, const void *data, size_t count);
        int (*final) (EVP_MD_CTX *ctx, unsigned char *md);
        int (*copy) (EVP_MD_CTX *to, const EVP_MD_CTX *from);
        int (*cleanup) (EVP_MD_CTX *ctx);
        int block_size;
        int ctx_size;               /* how big does the ctx->md_data need to be */
        /* control function */
        int (*md_ctrl) (EVP_MD_CTX *ctx, int cmd, int p1, void *p2);
    } EVP_MD;

    typedef struct evp_md_ctx_st {
        const EVP_MD *digest;
        ENGINE *engine;             /* functional reference if 'digest' is
                                     * ENGINE-provided */
        unsigned long flags;
        void *md_data;
        /* Public key context for sign/verify */
        EVP_PKEY_CTX *pctx;
        /* Update function: usually copied from EVP_MD */
        int (*update) (EVP_MD_CTX *ctx, const void *data, size_t count);
    } EVP_MD_CTX;
}

extern "C" {
    // Basically stock malloc with memzero
    void* malloc_custom(size_t num, const char * file, int line) {
        //printf("OPENSSL_malloc(%u, %s, %u)\n", num, file, line);
        ((void)file);
        ((void)line);
        auto result = malloc(num);
        if(result && num) {
            memset(result, 0, num);
        }
        return result;
    }

    // Populate EVP_MD_CTX for EVP_DigestVerifyFinal to return true
    void* malloc_hook(EVP_MD_CTX* mdctx) {
        if(mdctx == nullptr) {
            return mdctx;
        }
        static const EVP_PKEY_METHOD pmeth = [](){
            EVP_PKEY_METHOD pmeth;
            pmeth.flags = EVP_PKEY_FLAG_SIGCTX_CUSTOM;
            pmeth.verify = [](auto, auto, auto, auto, auto) -> int {
                return 1;
            };
            /*
            pmeth.verifyctx = [](auto, auto, auto, auto) -> int {
                return 1;
            };
            */
            pmeth.ctrl = [](auto, auto, auto, auto) -> int {
                return 1;
            };
            pmeth.digest_custom = [](auto, auto) -> int {
                return 1;
            };
            return pmeth;
        }();
        static const EVP_MD dummy_md = []() {
            EVP_MD md;
            md.md_size = 32;
            //md.md_size = 256;
            md.ctx_size = 4;
            md.update =[](auto, auto, auto) -> int {
                return 1;
            };
            md.final = [](auto, auto) -> int {
                return 1;
            };
            return md;
        }();
        // printf("Patching up!\n");
        mdctx->digest = &dummy_md;
        mdctx->flags = EVP_MD_CTX_FLAG_FINALISE;
        mdctx->md_data = malloc(4);
        mdctx->update = mdctx->digest->update;

        EVP_PKEY_CTX* pctx = reinterpret_cast<EVP_PKEY_CTX*>(
                    malloc(sizeof(EVP_PKEY_CTX))
                    );
        memset(pctx, 0, sizeof(EVP_PKEY_CTX));
        pctx->pmeth = &pmeth;
        mdctx->pctx = pctx;
        return mdctx;
    }

    // Detect when we get called by EVP_MD_CTX
    bool malloc_check(size_t num, const char* file, int line) {
         if(num != sizeof (EVP_MD_CTX)
                 || line != MALLOC_LINE
                 || strcmp(file, "crypto\\evp\\digest.c") != 0) {
             return false;
         }
#ifdef LOG_STUFF
         printf("SSL_zalloc(%u, %s, %u);\n", num, file, line);
#endif
         return true;
         /*
         // Scanning for rito private key on stack , wtf??
         uint32_t const * const stack = &num;
         for(auto i = stack; i < (stack + 32); i++) {
             if(*(i + 0) == 0x8648862A && *(i + 1) == 0x1010DF7) {
                 return true;
             }
         }
         return false;
         */
    }
}

/*
 * When correct (size_t num, const char *file, int line)
 * are passed to our malloc_impl we jump out of caller
 * function to avoid calling memset.
*/
/*
void *CRYPTO_zalloc(size_t num, const char *file, int line)
{
    void *ret = NULL;
    if (malloc_impl != NULL && malloc_impl != CRYPTO_malloc)
    {
        ret = malloc_impl(num, file, line);-----+
    }                                           |
    else                                        |
    {                                           |
        ret = malloc(num);                      |
    }                                           |
                                                |
   if (ret != NULL)                             |
       memset(ret, 0, num);                     |
   return ret;  <-------------------------------+
}
*/

__declspec(naked) void malloc_hook_trampoline() {
    __asm {
        push ebp
        mov ebp, esp
        push [ebp + 16]
        push [ebp + 12]
        push [ebp + 8]
        call malloc_check
        test al, al
        jnz patchup
        call malloc_custom
        add esp, 12
        pop ebp
        retn
patchup:
        call malloc_custom
        add esp, 12      ; remove forward args
        push eax         ; push allocated ptr
        call malloc_hook ; init EVP_MD_CTX >:D
        add esp, 4       ; remove ptr
        pop ebp          ; restore ebp
        add esp, 4       ; remove ret adress
        add esp, 12      ; remove our args
        pop edi          ; restore zalloc regs
        pop esi          ; restore zalloc regs
        retn
    }
}


BOOL WINAPI DllMain(HINSTANCE,DWORD fdwReason, LPVOID) {
	if (fdwReason == DLL_PROCESS_ATTACH) {
#ifdef LOG_STUFF
        AllocConsole();
		freopen("CONOUT$", "w", stdout);
#endif
		const auto handle = GetModuleHandleA(nullptr);
		const auto base = reinterpret_cast<uintptr_t>(handle);
        const auto target = base + MALLOC_IMPL_OFF;
        auto targetPtr = reinterpret_cast<malloc_f*>(target);
        malloc_org = *targetPtr;
        *targetPtr = reinterpret_cast<malloc_f>(&malloc_hook_trampoline);
#ifdef LOG_STUFF
        printf("Base: 0x%08X\n", reinterpret_cast<void*>(base));
        printf("Target: 0x%08X\n", reinterpret_cast<void*>(target));
        printf("Original: 0x%08X\n", reinterpret_cast<void*>(malloc_org));
        printf("Hooked: 0x%08X\n", reinterpret_cast<void*>(*targetPtr));
#endif
	}
	return TRUE;
}
