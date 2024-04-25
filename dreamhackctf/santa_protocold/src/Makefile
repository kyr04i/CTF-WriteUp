#Makefile
default: 
	gcc -o santa_protocold main.c net_helper.c -fpie -Wl,-z,relro,-z,now -fstack-protector

clean:
	rm -f santa_protocold
