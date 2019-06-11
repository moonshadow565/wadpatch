A .DLL to inject in League of Legends.exe to patch out .wad integrity checks.

It works by patching out OpenSSL memory allocation function to skip memset zeroing and fills dummy EVP_MD_CTX.

```cpp
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
```
