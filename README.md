# Teraki

## Table of contents
* [General info](#general-info)
* [Motivation](#motivation)
* [Technologies](#technologies)
* [Build system](#build-system)
* [Setup](#setup)
* [Run](#run)
* [Makefile](#makefile)
* [Credits](#credits)

## General info
This project creates and sets up a client and server nodes on a network to communicate with each other. The client reads plaintext from a file, encrypts it, and sends the ciphertext to the server. The server receives the ciphertext and prints the decrypted text to standard output. 

## Motivation
This project is a part of application process for Embedded C team, Software Engineer Internship position at Teraki.

## Technologies
Project is created with:
* gcc version: 9.3.0
* OpenSSL library version: 1.1.1f

## Build system 
This project uses GNU Make build system.
	
## Setup
To run this project, install OpenSSL library locally:
```
sudo apt-get install libssl-dev
```

## Run
To make server,
```
make -f server.mak PORT="8080" all
```
(If you change port argument, you need to assign the new value to macro in Client.c)

To make client,
```
make -f client.mak F_NAME="file.txt" S_ADDR="127.0.0.1" all
```

## Makefile
When editing makefile, always put links to crypto libraries(-lcrypto, -lssl) after object files. 
Linker reads each file only once and object file has to be read first so, the linker finds all refrences in libraries.

## Credits

[Openssl Wiki for EVP encryption and decryption](https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption)
[Geeks for Geeks tutorial for TCP Server-Client implementation in C](https://www.geeksforgeeks.org/tcp-server-client-implementation-in-c/)
