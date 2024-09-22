## dexdump

A simple CLI tool to dump .dex codes in memory. Without `ptrace`.

Made for a specific protection. May not work for all packers.

## Usage

```shell
dexdump <Process Name>
```

The dumped .dex file will be saved in the current working directory.

## Build

First, clone the repository:

```shell
git clone https://github.com/lihe07/dexdump
cd ./dexdump
```

Ensure the path to NDK clang in the Makefile is correct.
Then, build the project:

```shell
make
```

This will generate the executable `dexdump` in the current directory.
