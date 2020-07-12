#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

#define MAX 128
#define PORT 3333

int readFile(char *fname, 
             unsigned char *plaintext);
int encrypt(unsigned char *plaintext,
             unsigned char *ciphertext);
void handleErrors(void);
int gcm_encrypt(unsigned char *plaintext, int plaintext_len,
                unsigned char *aad, int aad_len,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *ciphertext,
                unsigned char *tag);

int sendToServer(unsigned char *ciphertext, char *server_address){
    int sockfd, connfd; 
    struct sockaddr_in servaddr, cli; 

    // socket create and verification 
    sockfd = socket(AF_INET, SOCK_STREAM, 0); 
    if (sockfd == -1) { 
        printf("socket creation failed...\n"); 
        exit(0); 
    } 
    else
        printf("Socket successfully created..\n"); 
    bzero(&servaddr, sizeof(servaddr)); 

    // assign IP, PORT 
    servaddr.sin_family = AF_INET; 
    servaddr.sin_addr.s_addr = inet_addr(server_address); 
    servaddr.sin_port = htons(PORT); 

    // connect the client socket to server socket 
    if (connect(sockfd, (SA*)&servaddr, sizeof(servaddr)) != 0) { 
        printf("connection with the server failed...\n"); 
        exit(0); 
    } 
    else
        printf("connected to the server..\n"); 

    // function for sending
    write(sockfd, ciphertext, sizeof(ciphertext)); 

    // close the socket 
    close(sockfd); 
}

int main(int argc, char *argv[])
{
    unsigned char plaintext[MAX];

    //second argument: file name
    int plaintext_len = readFile(argv[1], plaintext);

    if(plaintext_len<0){
        printf("reading from file failed");
    }

    /* Buffer for ciphertext.  */
    unsigned char ciphertext[128];

    int ciphertext_len = encrypt(plaintext, ciphertext);

    if(ciphertext_len>0){
        printf("Ciphertext is:\n");
        BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);
    }else{
        printf("encryption failed");
    }

    /* 
    * Send the ciphertext to server 
    * the third argument is server address
    */
    
    sendToServer(argv[2]);
    //sendToServer("127.0.0.1");

    return 0;
}

int readFile(char *fname, 
             unsigned char* plaintext){
    //Read File
    FILE *fp;
    /* Open the file of passed file name */
    fp  = fopen(fname, "r");
    if(fp == NULL)
    {
        printf("could not read from file %s\n", fname);
        return -1;
    }
    /* Read the message to be encrypted */
    fgets(plaintext, MAX, fp); 
    fclose (fp);

    int plaintext_len = strlen((char *)plaintext);

    if(plaintext_len>0){
        return plaintext_len;
    }else {
        return -1;
    }
}

int encrypt(unsigned char* plaintext, unsigned char *ciphertext){
    /* Set up the key and iv. Do not hard code these in a real application. */

    /* A 256 bit key */
    unsigned char *key = (unsigned char *)"01234567890123456789012345678901";

    /* A 128 bit IV */
    unsigned char *iv = (unsigned char *)"0123456789012345";
    size_t iv_len = 16;

    /* Additional data */
    unsigned char *additional =
        (unsigned char *)"Accurate and efficient edge processing.";

    /* Buffer for the tag */
    unsigned char tag[16];

    int decryptedtext_len, ciphertext_len;

    /* Encrypt the plaintext */
    ciphertext_len = gcm_encrypt(plaintext, strlen ((char *)plaintext),
                                 additional, strlen ((char *)additional),
                                 key,
                                 iv, iv_len,
                                 ciphertext, tag);
    return ciphertext_len;
}

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

int gcm_encrypt(unsigned char *plaintext, int plaintext_len,
                unsigned char *aad, int aad_len,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *ciphertext,
                unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;


    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /* Initialise the encryption operation. */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        handleErrors();

    /*
     * Set IV length if default 12 bytes (96 bits) is not appropriate
     */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        handleErrors();

    /* Initialise key and IV */
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
        handleErrors();

    /*
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Get the tag */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
        handleErrors();

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}



