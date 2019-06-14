A .DLL to inject in League of Legends.exe to patch out .wad integrity checks.

It works by patching out OpenSSL EVP_PKEY_METHOD table list(standard_methods).

The table can be found in OpenSSL source code defined in crypto\evp\pmeth_lib.c

The .dll expect wadpatch.txt in game's directory with a working offset.
