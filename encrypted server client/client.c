#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
#include<sys/socket.h>
#include<sys/types.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<openssl/rsa.h>
#include<openssl/pem.h>
int sock;
char *kuname;
RSA *ku, *kv, *sku;

RSA* genKey(char *fname, int pub)
{
    FILE *f=fopen(fname, "rb");
    if(f==NULL)
    {
        fprintf(stderr, "\n[-]Error in opening %s key location\n", fname);
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
    if(argc!=4)
    {
        fprintf(stderr, "\n[!]Usage\n ./client [pub_key.pem] [priv_key.pem] [server_addr:server_process_port]\n");
        _exit(-1);
    }
    
    //sock
    if((sock=socket(AF_INET, SOCK_STREAM, 0))<0)
    {
        fprintf(stderr, "\n[-]Error in creating socket\n");
        _exit(-1);
    }

    char *ip=strtok(argv[3], ":");
    char *portStr=strtok(NULL, ":");
    int port=(int)strtol(portStr, NULL, 10);
    printf("\n[!]Connecting to server at %s:%d\n", ip, port);
    //addr
    struct sockaddr_in addr;
    addr.sin_port=htons(port);
    addr.sin_addr.s_addr=inet_addr(ip);
    addr.sin_family=AF_INET;

    //connect
    if(connect(sock, (struct sockaddr*)&addr, sizeof(addr))<0)
    {
        fprintf(stderr, "\n[-]Error in connection to %s:%d\n", ip, port);
        _exit(-1);
    }

    ku=genKey(argv[1], 1);
    kv=genKey(argv[2], 0);
    if(ku==NULL || kv==NULL)
    {
        fprintf(stderr, "\n[-]Error in generating keys\n");
        _exit(-1);
    }

    //accept key
    printf("\n[!]Receving server public key\n");
    char *buf=(char*)malloc(1500*sizeof(char));
    if(recv(sock, buf, 1500*sizeof(char), 0)<0)
    {
        fprintf(stderr, "\n[-]Error in receving server public key\n");
        _exit(-1);
    }
    printf("\n[!]Received:\n%s\n", buf);
    FILE *f=fopen("sku.pem", "w");
    for(int i=0; i<1500; i++)
    {
        fprintf(f, "%c", buf[i]);
    }
    fclose(f);
    sku=genKey("sku.pem", 1);
    if(sku==NULL)
    {
        fprintf(stderr, "\n[-]Error in generating server public key for %s:%d\n", ip, port);
        _exit(-1);
    }
    free(buf);

    //send key
    f=fopen(argv[1], "r");
    if(f==NULL)
    {
        fprintf(stderr, "\n[-]Error in opening %s for sending\n", argv[1]);
        _exit(-1);
    }
    buf=(char*)malloc(1500*sizeof(char));
    char *buf_en=(char*)malloc(1500*sizeof(char));
    if(buf==NULL || buf_en==NULL)
    {
        fprintf(stderr, "\n[-]Error in creating placeholder for reading in public key, resources unavailable\n");
        _exit(-1);
    }
    explicit_bzero(buf, sizeof(char)*1500);
    explicit_bzero(buf_en, sizeof(char)*1500);
    for(int i=0; !feof(f); i++)
    {
        fscanf(f, "%c", &buf[i]);
    }
    if(RSA_public_encrypt(RSA_size(sku)-11, buf, buf_en ,sku, RSA_PKCS1_PADDING)<0)
    {
        fprintf(stderr, "\n[-]Error in encrypting public key for sending\n");
        _exit(-1);
    }
    
    printf("\n[!]Sending self public key:\n%s\n", buf);
    if(send(sock, buf_en, 1500*sizeof(char), 0)<0)
    {
        fprintf(stderr, "\n[-]Error in sending encrypted keublic key\n");
        _exit(-1);
    }

    //recv commands
    printf("\n[!]All registering done\n");
    
    char *cmdr_en=(char*)allocate("char", 1024);
    char *cmdr=(char*)allocate("char" ,25);
    if(cmdr_en==NULL || cmdr==NULL)
    {
        fprintf(stderr, "\n[-]Error in creating placeholder for receving the commands\n");
        _exit(-1);
    }
    if(recv(sock, cmdr_en, 1024*sizeof(char), 0)<0)
    {
        fprintf(stderr, "\n[-]Recv of command failed\n");
        _exit(-1);
    }
    if(RSA_private_decrypt(RSA_size(kv), cmdr_en, cmdr, kv, RSA_PKCS1_PADDING)<0)
    {
        fprintf(stderr, "\n[-]Error in decrypting the received command\n");
        _exit(-1);
    }
    printf("\n[+] %s\n", cmdr);
    explicit_bzero(cmdr, 25*sizeof(char));
    explicit_bzero(cmdr_en, 25*sizeof(char));
    return 0;

}
