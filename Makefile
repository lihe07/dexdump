
CC=${ANDROID_NDK}/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android35-clang

dexdump: main.c
	$(CC) -O2 -o dexdump main.c

.PHONY: clean
clean:
	rm -f dexdump
