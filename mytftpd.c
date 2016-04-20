#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <assert.h>
#include <signal.h>
#include <sys/signal.h>
#include <sys/select.h>

void printError(unsigned blockOrError, char *data1);
static void die(const char* msg);
static void* xmalloc(unsigned n);
void intHandler(int v, siginfo_t* si, void *unused);
void setSigHandler();
void closefd(int *f);
int checkSize(int size, const char *msg);
int strlensz(char *str, int max);
uint16_t randBetw(int min, int max);
void parseNextData(char *to, char *buffer, int len);
void parseNextString(char *to, char **buffer, int *sz);
void parseBytes(unsigned *to, char **buffer, int *sz, int cnt);
void parse(char **buffer, int *sz, unsigned *opcode, unsigned *blockOrError,
        char **data1, char **data2);
int validatePath(char *path);
FILE *checkAndOpenFile(char *path, const char *mode);
static int prepare_socket(int port, char *portMsg, char *addrMsg);
void sendPacket(int f, char *packet, int len);
void makePacket(char *packet, unsigned opcode, unsigned block, char *data,
        unsigned len);
int waitForPacket(char *lastPacket, int size);
int recvPacket(char **buffer, unsigned *opcode, unsigned *blockOrError,
        char **data1, char **data2, unsigned block);
void processRead(char **buffer, unsigned *opcode, unsigned *blockOrError,
        char **data1, char **data2);
void processWrite(char **buffer, unsigned *opcode, unsigned *blockOrError,
        char **data1, char **data2);
void processRequest(char *buffer, int sz);
static void waitForRequest(char *buffer, uint16_t port);

int         fd;
int         fd2;
fd_set      readFds;
struct      sockaddr *saddr;
socklen_t   *slen;
in_addr_t   preAddr;
bool        term;
static bool debug = false;

void printError(unsigned blockOrError, char *data1)
{
    printf("Error code %d: %s\n", blockOrError, data1);
}

static void die(const char* msg)
{
    perror(msg);
    exit(1);
}

static void* xmalloc(unsigned n)
{
    void *p;

    p = malloc(n);
    if (!p)
        die("malloc");
    return p;
}

void intHandler(int v, siginfo_t* si, void *unused)
{
    printf("\nserver stopped\n");
    term = true;
}

void setSigHandler()
{
    struct sigaction act;

    term = false;
    sigaction(SIGINT, 0, &act);
    act.sa_sigaction = intHandler;
    act.sa_flags |= SA_SIGINFO;
    sigaction(SIGINT, &act, 0);
}

void closefd(int *f)
{
    shutdown(*f, -2);
    close(*f);
    *f = 0;
}

int checkSize(int size, const char *msg)
{
    if (size == 0 || (size == -1 && (errno == EAGAIN || errno == EINTR)))
        return -1;
    else if (size == -1)
        die(msg);

    return 0;
}

int strlensz(char *str, int max)
{
    int i;

    i = 0;
    while (str[i] != '\0' && i < max)
        i++;

    return i;
}

uint16_t randBetw(int min, int max)
{
    return (unsigned short)((rand() % (max - min)) + min);
}

void parseNextData(char *to, char *buffer, int len)
{
    memmove(to, buffer, (long unsigned int)len);
}

void parseNextString(char *to, char **buffer, int *sz)
{
    int len;

    len = strlensz(*buffer, *sz);
    parseNextData(to, *buffer, len + 1);
    *buffer += (len + 1);
    *sz -= (len + 1);
}

void parseBytes(unsigned *to, char **buffer, int *sz, int cnt)
{
    *to = 0;
    for (cnt = 0; cnt < 2; cnt++)
    {
        *to <<= 8;
        *to |= **buffer & 0xFF;
        (*buffer)++;
        (*sz)--;
    }
}

void parse(char **buffer, int *sz, unsigned *opcode, unsigned *blockOrError,
        char **data1, char **data2)
{
    char *origBuffer;

    origBuffer = *buffer;
    parseBytes(opcode, buffer, sz, 2);
    if (*opcode == 1 || *opcode == 2)
    {
        parseNextString(*data1, buffer, sz);
        parseNextString(*data2, buffer, sz);
    }
    else if (*opcode == 3)
    {
        parseBytes(blockOrError, buffer, sz, 2);
        parseNextData(*data1, *buffer, *sz);
    }
    else if (*opcode == 4)
    {
        parseBytes(blockOrError, buffer, sz, 2);
    }
    else if (*opcode == 5)
    {
        parseBytes(blockOrError, buffer, sz, 2);
        parseNextData(*data1, *buffer, *sz);
    }
    *buffer = origBuffer;
}

int validatePath(char *path)
{
    long unsigned int i;
    long unsigned int len;

    if (path[0] == '.' && path[1] == '.')
        return -1;

    if (path[0] != '/')
        return 0;

    char cwd[1024];
    if (getcwd(cwd, sizeof(cwd)) == NULL)
        die("getcwd() error");

    len = strlen(cwd);
    if (strlen(path) < len)
    {
        return -1;
    }
    for (i = 0; i < len; i++)
    {
        if (cwd[i] != path[i])
            return -1;
    }
    return 0;
}

FILE *checkAndOpenFile(char *path, const char *mode)
{
    if (validatePath(path) == -1 && !debug)
    {
        sendto(fd2, "\0\5\0\2Access violation\0", 21, 0, saddr, *slen);
        return NULL;
    }
    if (strcmp(mode, "w") == 0 && access(path, F_OK) != -1)
    {
        sendto(fd2, "\0\5\0\6File already exists\0", 24, 0, saddr, *slen);
        return NULL;
    }
    if (strcmp(mode, "r") == 0 && access(path, F_OK) == -1)
    {
        sendto(fd2, "\0\5\0\1File not found\0", 19, 0, saddr, *slen);
        return NULL;
    }
    return fopen(path, mode);
}

static int prepare_socket(int port, char *portMsg, char *addrMsg)
{
    int                 f;
    struct sockaddr_in  addr;
    int                 retryPort;

    f = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (-1 == f)
        die("socket");

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(preAddr);

    if (port != 0)
        addr.sin_port = htons(port);
    else
        addr.sin_port = htons((randBetw(49152, 65535))); //random ephemeral port

    retryPort = 0;
    while (bind(f, (struct sockaddr*)&addr, sizeof(addr)) < 0)
    {
        addr.sin_port = htons(randBetw(49152, 65535));
        if (retryPort > 9 || port != 0)
            die("bind");

        retryPort++;
    }

    if (addrMsg != NULL && preAddr != 0)
        printf("%s%x\n", addrMsg, ntohl(addr.sin_addr.s_addr));

    printf("%s%u\n", portMsg, (unsigned)ntohs(addr.sin_port));

    return f;
}

void sendPacket(int f, char *packet, int len)
{
    int sz;

    sz = (int)sendto(f, packet, (unsigned long)len, 0, saddr, *slen);
    if (checkSize(sz, "send") == -1)
        die("send");
}

void makePacket(char *packet, unsigned opcode, unsigned block, char *data,
        unsigned len)
{
    packet[0] = (char)((opcode >> 8) & 0xFF);
    packet[1] = (char)(opcode & 0xFF);
    packet[2] = (char)((block >> 8) & 0xFF);
    packet[3] = (char)(block & 0xFF);
    if (len > 0)
        memmove(packet + 4, data, len);
}

int waitForPacket(char *lastPacket, int size)
{
    int             retry;
    int             t;
    struct timeval  stTimeOut;

    retry = t = 0;
    do
    {
        stTimeOut.tv_sec = 5;
        stTimeOut.tv_usec = 0;
        t = select(fd2 + 1, &readFds, (fd_set *)0, (fd_set *)0, &stTimeOut);
        if (t == -1)
            die("select");

        if (t == 0)
        {
            printf("timeout, retry\n");
            retry++;
            sendPacket(fd2, lastPacket, size);
        }
    }
    while (t < 1 && retry < 3);
    if (retry >= 3)
    {
        printf("aborted\n");
        return -1;
    }
    return 0;
}

int recvPacket(char **buffer, unsigned *opcode, unsigned *blockOrError,
        char **data1, char **data2, unsigned block)
{
    int bytes;

    bytes = (int)recvfrom(fd2, *buffer, 1024, 0, saddr, slen);
    if (checkSize(bytes, "recv") == -1)
        return 0;

    parse(buffer, &bytes, opcode, blockOrError, data1, data2);

    if (*opcode == 5)
    {
        printError(*blockOrError, *data1);
        return -1;
    }
    if ((*opcode != 3 && *opcode != 4) || *blockOrError != block)
        return 0;

    return bytes;
}

void processRead(char **buffer, unsigned *opcode, unsigned *blockOrError,
        char **data1, char **data2)
{
    unsigned    block;
    char        *dataPacket;
    FILE        *f;
    int         bytes;
    long        totalBytes;

    if (NULL == (f = checkAndOpenFile(*data1, "r")))
    {
        sendPacket(fd2, "\0\5\0\0Cannot open or create file\0", 31);
        return;
    }

    dataPacket = xmalloc(1024);
    block = 0;
    bytes = 512;
    totalBytes = 0;
    while (!term)
    {
        if (bytes < 512)
        {
            printf("send %ld bytes in %u blocks\n", totalBytes, *blockOrError);
            break;
        }

        if (512 != (bytes = (int)fread(*data1, 1, 512, f)) && feof(f) == 0)
        {
            sendPacket(fd2, "\0\5\0\0disk read error\0", 20);
            break;
        }
        block++;
        if (block >= 65535)
        {
            sendPacket(fd2, "\0\5\0\3Disk full or allocation exceeded\0", 37);
            break;
        }
        makePacket(dataPacket, 3u, block, *data1, bytes);
        sendPacket(fd2, dataPacket, 4 + bytes);
        if (waitForPacket(dataPacket, bytes) == -1)
            break;

        if ((recvPacket(buffer, opcode, blockOrError, data1, data2, block))
                == -1)
            break;

        totalBytes += (long)bytes;
    }
    fclose(f);
    free(dataPacket);
}

void processWrite(char **buffer, unsigned *opcode, unsigned *blockOrError,
        char **data1, char **data2)
{
    unsigned    block;
    char        ackPacket[4];
    FILE        *f;
    int         bytes;
    long        totalBytes;

    block = -1u;
    bytes = 512;
    totalBytes = 0;
    if (NULL == (f = checkAndOpenFile(*data1, "w")))
    {
        sendPacket(fd2, "\0\5\0\0Cannot open or create file\0", 31);
        return;
    }

    while (!term)
    {
        block++;
        if (block >= 65535)
        {
            sendPacket(fd2, "\0\5\0\3Disk full or allocation exceeded\0", 37);
            break;
        }
        makePacket(ackPacket, 4, block, "", 0);
        sendPacket(fd2, ackPacket, 4);
        if (bytes < 512)
        {
            printf("written %ld bytes in %u blocks\n", totalBytes, *blockOrError);
            break;
        }
        if (waitForPacket(ackPacket, 4) == -1)
            break;

        if ((bytes = recvPacket(buffer, opcode, blockOrError, data1, data2,
                block + 1)) == -1)
            break;

        if ((int)fwrite(*data1, 1, bytes, f) != bytes)
        {
            sendPacket(fd2, "\0\5\0\3Disk full or allocation exceeded\0", 37);
            break;
        }
        totalBytes += (long)bytes;
    }
    fclose(f);
}

void processRequest(char *buffer, int sz)
{
    unsigned    opcode;
    unsigned    blockOrError;
    char        *data1;
    char        *data2;

    data1 = xmalloc(1024);
    data2 = xmalloc(1024);
    parse(&buffer, &sz, &opcode, &blockOrError, &data1, &data2);
    if (strcmp(data2, "octet") != 0)
    {
        sendPacket(fd, "\0\5\0\0octet only\0", 15);
        return;
    }
    if (opcode < 1 || opcode > 2)
    {
        sendPacket(fd, "\0\5\0\4Illegal TFTP operation\0", 28);
        return;
    }

    if (opcode == 1)
        processRead(&buffer, &opcode, &blockOrError, &data1, &data2);
    else if (opcode == 2)
        processWrite(&buffer, &opcode, &blockOrError, &data1, &data2);

    free(data1);
    free(data2);
}

static void waitForRequest(char *buffer, uint16_t port)
{
    int sz;

    srand(time(NULL));
    fd = prepare_socket(port, "Socket opened, listening on port ",
            "Bind to IP address: ");
    fd2 = prepare_socket(0, "Data port: ", NULL);
    FD_ZERO(&readFds);
    FD_SET(fd2, &readFds);
    while (!term)
    {
        sz = recvfrom(fd, buffer, 1024, 0, saddr, slen);
        if (checkSize(sz, "recv") == -1)
            continue;

        processRequest(buffer, sz);
    }
}

int main(int argc, char *argv[])
{
    char        *buffer;
    uint16_t    port;

    if (argc == 1)
    {
        preAddr = INADDR_ANY;
        port = 0;
    }
    if (argc > 1)
        port = strtoul(argv[1], NULL, 10);
    if (argc > 2)
        preAddr = strtoul(argv[2], NULL, 16);

    setSigHandler();

    buffer = xmalloc(1024);
    saddr = xmalloc(sizeof(struct sockaddr));
    slen = xmalloc(sizeof(socklen_t));
    *slen = sizeof(struct sockaddr);

    waitForRequest(buffer, port);

    free(buffer);
    free(saddr);
    free(slen);
    printf("resources freed\n");
    return 0;
}
