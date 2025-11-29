Ilias Kapsis csd4652
Isidoros Chatzichrysos csd4338
Valerios Grammatikakis csd4616



Notes:  A phase of microtcp project . We run cmake and our files with wsl- linux terminal  , if for some reason run on windows remove the comment mark on line 31 of miscrotcp. h and keep #include <ws2tcpip.h> and remove includes that only linux has. CMAKE  will tell include errors in windows systems. 

# microTCP
A lightweight TCP implementation using UDP transport layer.

This is the class project for CS-335a (www.csd.uoc.gr/~hy335a/) for the
Fall 2023 semester.

## Build requirements
To build this project `cmake` is needed.

## Build instructions
```bash
mkdir build
cd build
cmake ..
make
```
