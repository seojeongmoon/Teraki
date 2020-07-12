#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

#define MAX 128

void handleErrors(void);

int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *aad, int aad_len,
                unsigned char *tag,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *plaintext);

int main(int argc, char *argv[]){
    /*
     * Set up the key and iv. Do not hard code these in a real application.
     */

    /* A 256 bit key */
    unsigned char *key = (unsigned char *)"01234567890123456789012345678901";

    /* A 128 bit IV */
    unsigned char *iv = (unsigned char *)"0123456789012345";
    size_t iv_len = 16;

    /* Additional data */
    unsigned char *additional =
        (unsigned char *)"Accurate and efficient edge processing.";
    
    /* Buffer for the ciphertext*/
    unsigned char ciphertext[128];
    
    /* Buffer for the decrypted text */
    unsigned char decryptedtext[128];

    /* Buffer for the tag */
    unsigned char tag[16];

    int decryptedtext_len;

    //temporary code. ciphertext will be assigned what this server receives from the client
    unsigned char text[] =  "hello";
    *ciphertext = text[0];

    printf("decryption entered\n");

    /* Decrypt the ciphertext */
    decryptedtext_len = gcm_decrypt(ciphertext, strlen ((char *)ciphertext),
                                    additional, strlen ((char *)additional),
                                    tag,
                                    key, iv, iv_len,
                                    decryptedtext);

    printf("decryption finished\n");

    if (decryptedtext_len >= 0) {
        /* Add a NULL terminator. We are expecting printable text */
        decryptedtext[decryptedtext_len] = '\0';

        /* Show the decrypted text */
        printf("Decrypted text is:\n");
        printf("%s\n", decryptedtext);
    } else {
        printf("Decryption failed\n");
    }

	return 0;
}

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *aad, int aad_len,
                unsigned char *tag,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();
    
    printf("context created and initialized\n");

    /* Initialise the decryption operation. */
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        handleErrors();

    printf("decryption operation initialized\n");


    /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        handleErrors();

    printf("set IV length\n");


    /* Initialise key and IV */
    if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
        handleErrors();

    printf("key and IV initialized\n");
    /*
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
    if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
        handleErrors();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

        printf("message to be decrypted\n");


    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
        handleErrors();

        printf("set expected tag value\n");

    /*
     * Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    printf("decryption finalised\n");

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    printf("cleaned up\n");

    printf("plaintext_len: %d, len: %d\n", plaintext_len, len);

    if(ret > 0) {
        /* Success */
        plaintext_len += len;
        return plaintext_len;
    } else {
        /* Verify failed */
        return -1;
    }
}