#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <string.h>
#include <stdlib.h>


#define DEFAULT_KEY_LEN 32  // 256 bits
#define DEFAULT_IV_LEN 16   // 128 bits
#define HASH_ITERATIONS 10000
#define SALT_LEN 16
#define HASH_LEN 32

int encrypt_data(const unsigned char *plaintext, int plaintext_len, const unsigned char *key, unsigned char *ciphertext);
int decrypt_data(const unsigned char *ciphertext, int ciphertext_len, const unsigned char *key, unsigned char *plaintext);

int encrypt_data(const unsigned char *plaintext, int plaintext_len, const unsigned char *key, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    printf("Encrypting data...\n");
    printf("Plaintext: ");
    for (int i = 0; i < plaintext_len; i++) {
        printf("%02x", plaintext[i]);
    }
    printf("\n");

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        fprintf(stderr, "Failed to create encryption context.\n");
        return -1;
    }

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        fprintf(stderr, "Encryption initialization failed.\n");
        return -1;
    }

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        fprintf(stderr, "Encryption update failed.\n");
        return -1;
    }
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        fprintf(stderr, "Encryption finalization failed.\n");
        return -1;
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    printf("Encrypted data: ");
    for (int i = 0; i < ciphertext_len; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    return ciphertext_len;
}

int decrypt_data(const unsigned char *ciphertext, int ciphertext_len, const unsigned char *key, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        return -1; // Error creating the context
    }

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1; // Error initializing the decryption
    }

    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1; // Error during decryption
    }
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1; // Error finalizing the decryption
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}
