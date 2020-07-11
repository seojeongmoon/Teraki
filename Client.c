#include <netdb.h> 
#include <stdio.h> 
#include <stdlib.h> 
#include <string.h> 
#include <sys/socket.h> 

#define MAX 8 
#define PORT 8080 
#define SA struct sockaddr 

int main(int argc, char *argv[])
{	
	FILE *fp;
	char content[MAX];
	fp  = fopen(argv[1], "r");
	if(fp == NULL)
    {
        printf("Could not create %s\n", argv[1]);
        return -1;
    }
	fgets(content, MAX, fp); 
	fclose (fp);
	printf("complete\n");
	return 0;
}
