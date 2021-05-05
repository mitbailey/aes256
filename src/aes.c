/**
 * @file aes.c
 * @author Mit Bailey (mitbailey99@gmail.com)
 * @brief 
 * @version 0.1
 * @date 2021-05-04
 * 
 * @copyright Copyright (c) 2021
 * 
 */

// https://stackoverflow.com/questions/42662733/evp-md-ctx-error-storage-size-of-ctx-isn-t-known/42666983

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>

// Works for coding.
//#include "include/aes.h"
//#include "include/aes_extern.h"

// Works for compiling.
#include <aes.h>
#include <aes_extern.h>

/*
aes.inf file contents
-------
99502           <-- salt[0]
92993           <-- salt[1]
apple           <-- password
*/

/**
 * @brief Tests the library.
 * 
 * @param argc 
 * @param argv En/decryptable data should be passed here.
 * @return int 
 */
int main(int argc, char **argv)
{
    // TODO: Implement tests.
    char input[] = "This is a test of the emergency broadcast system.";
    char plaintext[64];
    unsigned char ciphertext[64];
    int len;
    
    len = strlen(input)+1;
    
    aes_encrypt_data(input, sizeof(input), ciphertext, sizeof(plaintext));
    aes_decryp_data(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext));

    if (strncmp(plaintext, input, len)) 
      printf("FAIL: enc/dec failed for \"%s\"\n", input);
    else 
      printf("OK: enc/dec ok for \"%s\"\n", plaintext);
    
    free(ciphertext);
    free(plaintext);

    return SUCCESS;
}

int aes_encrypt_data(char* input, uint8_t inputLength, char* output, uint8_t outputLength)
{
    // Perform checks.
    // Check if we've been primed.
    // Check if our information matches the primed information.

    unsigned int salt[] = {99502, 92993};
    unsigned char key_data[] = "apple";
    int key_data_len = strlen(key_data);

    // Do what main does
    EVP_CIPHER_CTX *en;
    en = EVP_CIPHER_CTX_new();

    if (en == NULL)
    {
        return ERR_SET_CTX;
    }

    /* gen key and iv. init the cipher ctx object */
    if (aes_initialize(key_data, key_data_len, (unsigned char *)&salt, en))
    {
        printf("Couldn't initialize AES cipher.\n");
        return ERR_AES_INIT;
    }

    // Return aes_encrypt'd data.
    output = aes_encrypt(en, input, &inputLength);
    return SUCCESS;
}

int aes_decrypt_data(char* input, uint8_t inputLength, char* output, uint8_t outputLength)
{
    // Perform checks.
    // Check if we've been primed.
    // Check if our information matches the primed information.

    unsigned int salt[] = {99502, 92993};
    unsigned char key_data[] = "apple";
    int key_data_len = strlen(key_data);

    // Do what main does.
    EVP_CIPHER_CTX *de;
    de = EVP_CIPHER_CTX_new();

    if (de == NULL)
    {
        return ERR_SET_CTX;
    }

    if (aes_initialize(key_data, key_data_len, (unsigned char *)&salt, de))
    {
        printf("Couldn't initialize AES cipher.\n");
        return ERR_AES_INIT;
    }

    // Return aes_decrypt'd data.
    output = aes_decrypt(de, input, &inputLength);
    return SUCCESS;
}

int aes_initialize(unsigned char *key_data, int key_data_len, unsigned char *salt, EVP_CIPHER_CTX *ctx)
{
    int i, nrounds = 5;
    unsigned char key[32], iv[32];

    /*
   * Gen key & IV for AES 256 CBC mode. A SHA1 digest is used to hash the supplied key material.
   * nrounds is the number of times the we hash the material. More rounds are more secure but
   * slower.
   */
    i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, key_data, key_data_len, nrounds, key, iv);

    printf("DEBUG: The salt is %d.\n", *salt);
    printf("DEBUG: The key_data is %d.\n", *key_data);
    printf("DEBUG: The nrounds is %d.\n", nrounds);
    printf("DEBUG: The key is %d.\n", *key);
    printf("DEBUG: The IV is %d.\n", *iv);

    if (i != 32)
    {
        printf("Key size is %d bits but should be 256 bits\n", i);
        return -1;
    }

    EVP_CIPHER_CTX_init(ctx);
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    return 0;
}

unsigned char *aes_encrypt(EVP_CIPHER_CTX *e, unsigned char *plaintext, int *len)
{
    /* max ciphertext len for a n bytes of plaintext is n + AES_BLOCK_SIZE -1 bytes */
    int c_len = *len + AES_BLOCK_SIZE, f_len = 0;
    unsigned char *ciphertext = malloc(c_len);

    /* allows reusing of 'e' for multiple encryption cycles */
    EVP_EncryptInit_ex(e, NULL, NULL, NULL, NULL);

    /* update ciphertext, c_len is filled with the length of ciphertext generated,
    *len is the size of plaintext in bytes */
    EVP_EncryptUpdate(e, ciphertext, &c_len, plaintext, *len);

    /* update ciphertext with the final remaining bytes */
    EVP_EncryptFinal_ex(e, ciphertext + c_len, &f_len);

    *len = c_len + f_len;

    EVP_CIPHER_CTX_free(e);

    return ciphertext;
}

/*
 * Decrypt *len bytes of ciphertext
 */
unsigned char *aes_decrypt(EVP_CIPHER_CTX *e, unsigned char *ciphertext, int *len)
{
    /* plaintext will always be equal to or lesser than length of ciphertext*/
    int p_len = *len, f_len = 0;
    unsigned char *plaintext = malloc(p_len);

    EVP_DecryptInit_ex(e, NULL, NULL, NULL, NULL);
    EVP_DecryptUpdate(e, plaintext, &p_len, ciphertext, *len);
    EVP_DecryptFinal_ex(e, plaintext + p_len, &f_len);

    *len = p_len + f_len;

    EVP_CIPHER_CTX_free(e);

    return plaintext;
}