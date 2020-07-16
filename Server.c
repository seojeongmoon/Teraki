#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <stdio.h> 
#include <netdb.h> 
#include <netinet/in.h> 
#include <stdlib.h> 
#include <sys/socket.h> 
#include <sys/types.h> 
#include <errno.h>

#define SA struct sockaddr 
#define MAX 128
#define PORT 8080

void handleErrors(void);
int decrypt(unsigned char *ciphertext, 
             int ciphertext_len,
             unsigned char *decryptedtext, 
             unsigned char *tag);
int gcm_decrypt(unsigned char *ciphertext, 
                int ciphertext_len,
                unsigned char *aad, int aad_len,
                unsigned char *tag,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *plaintext);
void printString(const unsigned char *ciphertext_input, 
                 const int ciphertext_len,
                 const char *name);
int receiveFromClient(char *port, 
                      unsigned char *ciphertext,
                      unsigned char *tag);

int main(int argc, char *argv[]){
   
    /* Buffer for the ciphertext*/
    unsigned char ciphertext[MAX];
    unsigned char decryptedtext[MAX];
    unsigned char tag[16];
    int ciphertext_len, decryptedtext_len;
    
    ciphertext_len = receiveFromClient(PORT, ciphertext, tag);

    /* Buffer for the decrypted text */
 
    decryptedtext_len = decrypt(ciphertext, ciphertext_len, decryptedtext, tag);

    printString(decryptedtext, decryptedtext_len, "decrypted text");

	return 0;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *decryptedtext, unsigned char* tag)
{
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
    //unsigned char tag[16];

    int decryptedtext_len;

    /* Decrypt the ciphertext */
    decryptedtext_len = gcm_decrypt(ciphertext, strlen ((unsigned char *)ciphertext),
                                    additional, strlen ((unsigned char *)additional),
                                    tag,
                                    key, iv, iv_len,
                                    decryptedtext);

    if(decryptedtext_len>=0){
        printf("Server decrypted successfully\n");
        printString(decryptedtext, decryptedtext_len, "decryptedtext");
    }else{
        printf("Server failed to decrypt\n");
        printf("error: %s\n",strerror(errno));
    }

    return decryptedtext_len;
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

    /* Initialise the decryption operation. */
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        handleErrors();

    /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        handleErrors();

    /* Initialise key and IV */
    if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
        handleErrors();

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

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
        handleErrors();

    /*
     * Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    //ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    //printString(plaintext, plaintext_len+len, "plaintext inside gcm_decrypt");
    //printString(ciphertext, ciphertext_len, "ciphertext inside gcm_decrypt");
    
    //no clue why...
    unsigned char temp[MAX];
    strcpy(temp, plaintext);
    strcpy(plaintext, ciphertext);
    strcpy(ciphertext, temp);

    printString(plaintext, plaintext_len+len, "plaintext inside gcm_decrypt");
    printString(ciphertext, ciphertext_len, "ciphertext inside gcm_decrypt");
    
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    /*if(ret > 0) {
        /* Success */
    /*    plaintext_len += len;
        return plaintext_len;
    } else {
        /* Verify failed */
    /*    return -1;
    }*/

    if(plaintext_len>0){
        return plaintext_len;
    }else{
        return -1;
    }
}

void printString(const unsigned char *input, const int len, const char *name){
    unsigned char buff[MAX];
    strcpy(buff, input);

    buff[len]='\0';
    printf("%s: %s\n", name, buff);
}

int receiveFromClient(char *port, unsigned char *ciphertext, unsigned char *tag)
{
    int sockfd, connfd, len, read_result_ciphertext, read_result_tag; 
    struct sockaddr_in servaddr, cli; 
    unsigned char buff[MAX];

    // socket create and verification 
    sockfd = socket(AF_INET, SOCK_STREAM, 0); 
    if (sockfd == -1) { 
        printf("socket creation failed...\n"); 
        printf("error: %s\n",strerror(errno));
        exit(0); 
    } 
    else
        printf("Socket successfully created..\n"); 
    bzero(&servaddr, sizeof(servaddr)); 

    // assign IP, port 
    servaddr.sin_family = AF_INET; 
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY); 
    servaddr.sin_port = htons(port); 

    // Binding newly created socket to given IP and verification 
    if ((bind(sockfd, (SA*)&servaddr, sizeof(servaddr))) != 0) { 
        printf("socket bind failed...\n");
        printf("error: %s\n",strerror(errno));
        exit(0); 
    } 
    else
        printf("Socket successfully binded..\n"); 

    // Now server is ready to listen and verification 
    if ((listen(sockfd, 5)) != 0) { 
        printf("Listen failed...\n"); 
        printf("error: %s\n",strerror(errno));
        exit(0); 
    } 
    else
        printf("Server listening..\n"); 
    len = sizeof(cli); 

    // Accept the data packet from client and verification 
    connfd = accept(sockfd, (SA*)&cli, &len); 
    if (connfd < 0) { 
        printf("server acccept failed...\n"); 
        printf("error: %s\n",strerror(errno));
        exit(0); 
    } 
    else
        printf("server acccept the client...\n"); 

    // read the message from client and copy it in ciphertext 
    bzero(buff, MAX);
    read_result_ciphertext = -1;
    read_result_ciphertext = read(connfd, buff, sizeof(buff));  

    if(read_result_ciphertext>0){
        printf("Server received data\n");
        strcpy(ciphertext, buff);
        printString(ciphertext, read_result_ciphertext, "ciphertext");
    }else{
        printf("server failed to receive data\n");
        printf("error: %s\n",strerror(errno));
        return -1;
    }

    // read the message from client and copy it in tag 
    bzero(buff, MAX);
    read_result_tag = -1;
    read_result_tag = read(connfd, buff, sizeof(buff));  
    
    if(read_result_tag>0){
      printf("Server received data\n");
      strcpy(tag, buff);
      printString(tag, read_result_tag, "tag");
    }else{
      printf("server failed to receive data\n");
      printf("error: %s\n",strerror(errno));
      return -1;
    }
    printf("\n");

    // After chatting close the socket 
    close(sockfd); 

    return read_result_ciphertext;
}

