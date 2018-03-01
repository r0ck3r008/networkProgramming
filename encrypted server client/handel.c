#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<string.h>
#include<sys/socket.h>
#include<sys/types.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<sys/ipc.h>
#include<sys/shm.h>
#include<openssl/rsa.h>
#include<openssl/pem.h>
#include<errno.h>
#include<errno.h>
#include<fcntl.h>
#include<sys/stat.h>

struct client
{
    int id;
    struct sockaddr_in cliaddr;
    int clisock;
    int cxn;
} *shm=NULL;

RSA *cliku;
char *pipename;
int shmid, key=12345, pipefd;

RSA *genKey(char *fname, int pub)
{
    FILE *f=fopen(fname, "rb");
    if(f==NULL)
    {
        fprintf(stderr, "\n[-]Error in opening %s file\n", fname);
        _exit(-1);
    }

    RSA *rsa=RSA_new();

    if(pub)
    {
        rsa= PEM_read_RSA_PUBKEY(f, &rsa, NULL, NULL);
    }
    else
    {
        rsa= PEM_read_RSAPrivateKey(f, &rsa, NULL, NULL);
    }

    return rsa;
}


void* allocate(char *type, int size)
{
    void *ret;
    if(strcmp(type, "char")==0)
    {
        ret=malloc(size*sizeof(char));
        explicit_bzero(ret, size*sizeof(char));
    }
    else if(strcmp(type, "int")==0)
    {
        ret=malloc(size*sizeof(int));
        explicit_bzero(ret, size*sizeof(int));
    }
    if(ret==NULL)
    {
        fprintf(stderr, "\n[-]%s allocation of size %d failed, insufficient resources\n", type, size);
        _exit(-1);
    }

    return ret;
}


int main(int argc, char *argv[])
{
    int i=(int)strtol(argv[1], NULL, 10);
    //shmget
    if((shmid=shmget(key, 10*sizeof(struct client), 0644))<0)
    {
        fprintf(stderr, "\n[-]Error in getting shared memory id:\n");
        _exit(-1);
    }
    if((shm=(struct client*)shmat(shmid, NULL, 0))==NULL)
    {
        fprintf(stderr, "\n[-]Error in getting shared memory pointer\n");
        _exit(-1);
    }

    printf("\n[!]Handelling client at %s:%d with offset %d\n", inet_ntoa(shm[i].cliaddr.sin_addr), ntohs(shm[i].cliaddr.sin_port), shm[i].id);
    
    //generate key
    char *fname=(char*)allocate("char", 35);
    sprintf(fname, "key-[%s:%d].pem", inet_ntoa(shm[i].cliaddr.sin_addr), ntohs(shm[i].cliaddr.sin_port));
    cliku=genKey(fname, 1);
    free(fname);
    if(cliku==NULL)
    {
        fprintf(stderr, "\n[-]Key not passed on\n");
         _exit(-1);
    }

    //get command
    printf("\n[>] ");
    char *cmds=(char*)allocate("char", 10);
    char *cmds_en=(char*)allocate("char", 1024);
    fgets(cmds, 10*sizeof(char), stdin);
    printf("[!]RSA_size(ku)=%d\n", RSA_size(cliku));
    printf("[!]Message length %d\n", strlen(cmds));
    if(RSA_public_encrypt(strlen(cmds), cmds, cmds_en, cliku, RSA_PKCS1_PADDING)<0)
    {
        fprintf(stderr, "\n[-]Error in encrypting msg for client\n");
        _exit(-1);
    }
    printf("[!]Socket fd is: %d\n", shm[i].clisock);

    //open pipe
    pipename=(char*)allocate("char", 35);
    sprintf(pipename, "pipe-[%s:%d]", inet_ntoa(shm[i].cliaddr.sin_addr), ntohs(shm[i].cliaddr.sin_port));
    if((pipefd=open(pipename, O_RDWR))<0)
    {
        fprintf(stderr, "\n[-]Error in opening pipe: '%s'\n", strerror(errno));
        _exit(-1);
    }
    
    //write command
    if(write(pipefd, cmds_en, 1024*sizeof(char))<0)
    {
         fprintf(stderr, "\n[-]Error in writing to pipe %s: '%s'\n", cmds, strerror(errno));
        _exit(-1);
 
    }

    printf("\n[>] ");
    fgets(cmds, 10*sizeof(char), stdin);
    close(pipefd);

    free(cmds); free(cmds_en);
    return 0;
}
