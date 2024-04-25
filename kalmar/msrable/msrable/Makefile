all:
	gcc -T "linker.ld" -fPIE -nostdlib -static -Os -Wall -DNDEBUG -fno-exceptions -fno-asynchronous-unwind-tables -fno-unwind-tables -ffunction-sections -s -Wl,--print-gc-sections -Wl,--gc-sections -Wl,--build-id=none
clean:
	rm exploit

