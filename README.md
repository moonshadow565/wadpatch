Patch League of Legends.exe to remove .wad integrity checks.

It works by patching out OpenSSL EVP_PKEY_METHOD table list(standard_methods).

The table can be found in OpenSSL source code defined in crypto\evp\pmeth_lib.c
