# CROP

A lightweight and efficient tool to find ROP gadgets written entirely in C.

Only x86_64 ELF binaries are supported presently.

## Usage

./crop <executable>

## Requirements

* libcapstone-dev 

## Compilation

` gcc *.c -lcapstone -o crop`

## TODO

* Add x86_32 support
* Config options