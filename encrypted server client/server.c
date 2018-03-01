#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<string.h>
#include<sys/socket.h>
#include<sys/types.h>
#include<openssl/rsa.h>
#include<openssl/pem.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<sys/ipc.h>
#include<sys/shm.h>
#include<fcntl.h>
#include<sys/stat.h>
#include<errno.h>


struct client
{
    int id;
    struct sockaddr_in cliaddr;
    int clisock;
    int cxn;
} *shm;

int sock, shmid, key=12345;
char *kuname;
RSA *kv, *ku;

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

void *cli_run(void *a)
{
    struct client *cli=(struct client*)a;
    
    printf("\n[!]Accepted and running client: %s:%d\n", inet_ntoa(cli->cliaddr.sin_addr), ntohs(cli->cliaddr.sin_port));

    //send key
    FILE *f=fopen(kuname, "r");
    if(f==NULL)
    {
        fprintf(stderr, "\n[-]Error in opening %s for sending\n", kuname);
        pthread_exit(NULL);
    }
    char *buf=(char*)allocate("char", 1500);
    for(int i=0; !feof(f); i++)
    {
        fscanf(f, "%c", &buf[i]);
    }
    printf("\n[!]Sending as key(to %s:%d):\n%s\n", inet_ntoa(cli->cliaddr.sin_addr), ntohs(cli->cliaddr.sin_port), buf);
    if(send(cli->clisock, buf, 1500*sizeof(char), 0)<0)
    {
        fprintf(stderr, "\n[-]Error in sending public key to client %s:%s\n", inet_ntoa(cli->cliaddr.sin_addr), ntohs(cli->cliaddr.sin_port));
        pthread_exit(NULL);
    }
    free(buf);
    fclose(f);
    //accept key
    char *cmdr=(char*)allocate("char", 1500);
    char *cmdr_en=(char*)allocate("char", 1500);
    if(recv(cli->clisock, cmdr_en, 1500*sizeof(char), 0)<0)
    {
        fprintf(stderr, "\n[-]Error in recving encrypted public key from %s:%d\n", inet_ntoa(cli->cliaddr.sin_addr), ntohs(cli->cliaddr.sin_port));
        pthread_exit(NULL);
    }
    if(RSA_private_decrypt(RSA_size(ku), cmdr_en, cmdr, kv, RSA_PKCS1_PADDING)<0)
    {
        fprintf(stderr, "\n[-]Decryption of received key failed from %s:%d", inet_ntoa(cli->cliaddr.sin_addr), ntohs(cli->cliaddr.sin_port));
        pthread_exit(NULL);
    }
    printf("\n[!]Decrypted key from %s:%d:\n%s\n", inet_ntoa(cli->cliaddr.sin_addr), ntohs(cli->cliaddr.sin_port), cmdr);
    printf("\nclient is id'ed at %d with sockfd %d\n", cli->id, cli->clisock);
    char *fname=(char*)allocate("char", 35);
    sprintf(fname, "key-[%s:%d].pem", inet_ntoa(cli->cliaddr.sin_addr), ntohs(cli->cliaddr.sin_port));
    FILE *f2=fopen(fname, "w");
    for(int i=0; i<1500; i++)
    {
        fprintf(f, "%c", cmdr[i]);
    }
    fclose(f2);
    free(fname);
    
    //mkfifo
    printf("\n[!]Creating named pipe for the client %s:%d\n", inet_ntoa(cli->cliaddr.sin_addr), ntohs(cli->cliaddr.sin_port));
    char *pipename=(char*)allocate("char", 35);
    sprintf(pipename, "pipe-[%s:%d]", inet_ntoa(cli->cliaddr.sin_addr), ntohs(cli->cliaddr.sin_port));
    if(mkfifo(pipename, 0644)<0)
    {
        fprintf(stderr, "\n[-]Error in creating pipe for %s:%d '%s'", inet_ntoa(cli->cliaddr.sin_addr), ntohs(cli->cliaddr.sin_port), strerror(errno));
        pthread_exit(NULL);
    }
    int pipefd;

    if((pipefd=open(pipename, O_RDWR ))<0)
    {
        fprintf(stderr, "\n[-]Error in opening pipe for %s:%d: '%s'", inet_ntoa(cli->cliaddr.sin_addr), ntohs(cli->cliaddr.sin_port), strerror(errno));
        pthread_exit(NULL);
    }

    //start handler
    printf("[!]All done for the client %s:%d, starting handler now\n", inet_ntoa(cli->cliaddr.sin_addr), ntohs(cli->cliaddr.sin_port));
    char *handler=(char*)allocate("char", 35);
    sprintf(handler, "terminator -x ./handel %d", cli->id);

    printf("\n[!]Calling command %s\n", handler);
    if(fork()==0)
    {
        //child
        system(handler);
    }
    else
    {
        //parent
        char *cmdr=(char*)allocate("char", 1024);
        if(read(pipefd, cmdr, 1024*sizeof(char))<0)
        {
            fprintf(stderr, "\n[-]Error in reading from pipe %s: %s\n", pipename, strerror(errno));
            pthread_exit(NULL);
        }
        if(send(cli->clisock, cmdr, 1024*sizeof(char), 0)<0)
        {
            fprintf(stderr, "\n[-]Error in sending command to client %s:%d\n", inet_ntoa(cli->cliaddr.sin_addr), ntohs(cli->cliaddr.sin_port));
            pthread_exit(NULL);
        }
        printf("\n[!]Sent command to %s:%d\n", inet_ntoa(cli->cliaddr.sin_addr), ntohs(cli->cliaddr.sin_port));
           
    }
    
}

int main(int argc, char *argv[])
{
    if(argc!=4)
    {
        fprintf(stderr, "\nUsage:\n./server [pub_key.pem] [priv_key.pem] [ip_addr_to_bind:port_to_bind]\n");
        _exit(-1);
    }
    kuname=argv[1];
    
    //keys
    ku= genKey(argv[1], 1);
    kv= genKey(argv[2], 0);
    if(ku==NULL || kv==NULL)
    {
        fprintf(stderr, "\n[-]Error in parsing the provided keys\n");
        _exit(-1);
    }

    //sock
    if((sock=socket(AF_INET, SOCK_STREAM, 0))<0)
    {
        fprintf(stderr, "\n[-]Error in creating socket");
        _exit(-1);
    }

    char *ip=strtok(argv[3], ":");
    char *portStr=strtok(NULL, ":");
    int port=(int)strtol(portStr, NULL, 10);

    printf("\n[!]Binding to %s:%d\n", ip, port);

    //addr
    struct sockaddr_in addr;
    addr.sin_family=AF_INET;
    addr.sin_port=htons(port);
    addr.sin_addr.s_addr=inet_addr(ip);

    //bind
    if(bind(sock, (struct sockaddr*)&addr, sizeof(addr))<0)
    {
        fprintf(stderr, "\n[-]Bind failed\n");
        _exit(-1);
    }

    //listen
    if(listen(sock, 10)<0)
    {
        fprintf(stderr, "\n[-]Listen mode failed\n");
        _exit(-1);
    }

    //shm
    if((shmid=shmget(key, 10*sizeof(struct client), 0644 | IPC_CREAT))<0)
    {
        fprintf(stderr, "\n[-]Error in getting shmid\n");
        _exit(-1);
    }

    if((shm=(struct client*)shmat(shmid, NULL, 0))<0)
    {
        fprintf(stderr, "\n[-]Error in getting shm start pointer\n");
        _exit(-1);
    }
    explicit_bzero(shm, 10*sizeof(struct client));
    //accept
    printf("\n[!]Server starting on %s:%d, no errors were reported\n", ip, port);

    pthread_t *tid=(pthread_t*)malloc(10*sizeof(pthread_t));
    if(tid==NULL)
    {
        fprintf(stderr, "\n[-]Error in allocating placeholders for clients, resource unavailable\n");
        _exit(-1);
    }
    
    int i=-1;
    socklen_t len=sizeof(struct sockaddr_in);
    while(1)
    {
        while(i<10)
        {
            i++;
            if(i==10)
            {
                fprintf(stderr, "\n[-]Client limit %d excedeed, rejecting client\n", i);
                break;
            } 
            if((shm[i].clisock=accept(sock, (struct sockaddr*)&(shm[i].cliaddr), &len))<0)
            {
                fprintf(stderr, "\n[-]Client %s:%d accept failed\n", inet_ntoa(shm[i].cliaddr.sin_addr), ntohs(shm[i].cliaddr.sin_port));
                i--;
                continue;
            }

            shm[i].id=i;
            shm[i].cxn=1;

            if(pthread_create(&tid[i], NULL, cli_run, &shm[i])<0)
            {
                fprintf(stderr, "\n[-]Client %s:%d start failed", inet_ntoa(shm[i].cliaddr.sin_addr), ntohs(shm[i].cliaddr.sin_port));
                i--;
                continue;
            }
        }
    }

    return 0;

}
