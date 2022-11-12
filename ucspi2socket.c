#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <unistd.h>
#include <poll.h>
#include <errno.h>

#include "logmsg.h"

/* file descriptors for reading from and writing to network */
#define NETWORK_READ_FD                 0
#define NETWORK_WRITE_FD                1

/* after being idle for these many secs the connection is terminated */
#define TIMEOUT                         40

/* no command lines will ever be longer than this many bytes (adjust as you need) */
#define BUFLEN                          1024

extern int loglevel;

int main(int argc, char *argv[]) {
    /* connect to upstream server */
    int srvsock;
    struct sockaddr_in srvsa;
    struct pollfd fds[2];
    int ret, len, cnt;
    char srvaddr[16], buf[BUFLEN];
    unsigned short int srvport;


    logmsg_init("ucspi2socket: ");

    /* sanity checks */
    if (argc < 2) {
        logmsg(LOG_CRIT, "Specify upstream server IP as command line argument.");
        exit(100);
    }
    loglevel = LOG_DEBUG;
    
    /* set the log level */
    if (getenv("LOGTHRESHOLD") != NULL) {
        char *x = getenv("LOGTHRESHOLD");
        sscanf(x, "%u", & loglevel);
    }

    /* extract the address of the upstream server to connect to */
    sscanf(argv[1], "%s", srvaddr);

    /* determine the port number to connect to */
    if (argc < 3 || sscanf(argv[2], "%hu", & srvport) != 1) {
        /* port parameter missing, default to 25 */
        srvport = 25;
    }
    logmsg(LOG_DEBUG, "Got server address '%s' port %hu", srvaddr, srvport);

    /* preparing to connect to the upstream server */
    srvsock = socket(AF_INET, SOCK_STREAM, 0);
    if (srvsock < 0) {
        logmsg(LOG_ERR, "Unable to create socket: %s.", strerror(errno));
        exit(100);
    }

    srvsa.sin_family = AF_INET;
    srvsa.sin_port = htons(srvport);
    srvsa.sin_addr.s_addr = inet_addr(srvaddr);
    memset(& srvsa.sin_zero, 0x00, sizeof(srvsa.sin_zero));

    /* connecting */
    ret = connect(srvsock, (struct sockaddr *) &srvsa, sizeof(srvsa));
    if (ret != 0) {
        logmsg(LOG_ERR, "Unable to connect socket: %s\n", strerror(errno));
        exit(100);
    }
    logmsg(LOG_DEBUG, "Connected successfully to %s:%hu, socket %d", srvaddr, srvport, srvsock); 

    /* preparing the sockets for non-blocking I/O */
    fcntl(NETWORK_READ_FD, F_SETFL, O_NONBLOCK);
    fcntl(srvsock, F_SETFL, O_NONBLOCK);

    /* preparing for poll() */
    fds[0].fd = NETWORK_READ_FD;
    fds[0].events = POLLIN;

    fds[1].fd = srvsock;
    fds[1].events = POLLIN;

    /* exchange data */
    while ((ret = poll(fds, 2, TIMEOUT*1000)) != -1) {
        /* data to read */
        if (fds[0].revents & POLLIN) {
            /* client ---> server */
            len = read(NETWORK_READ_FD, buf, BUFLEN);
            if (len <= 0) exit(0);
            cnt = 0;
            do {    /* beware of srvsock being O_NONBLOCK ... */
                ret = write(srvsock, buf+cnt, len-cnt);
                if (ret < 0) {
                    logmsg(LOG_ERR, "Unable to write %d bytes to the server: %s", strerror(errno));
                    exit(100);
                }
                cnt += ret;
            } while (cnt < len);
        } else if (fds[1].revents & POLLIN) {
            /* server ---> client */
            len = read(srvsock, buf, BUFLEN);
            if (len <= 0) exit(0);
            if (write(NETWORK_WRITE_FD, buf, len) != len) {
                logmsg(LOG_ERR, "Unable to write %d bytes to the client.");
                write(srvsock, "QUIT\r\n", strlen("QUIT\r\n"));
                exit(0);
            }
        } else {
            logmsg(LOG_NOTICE, "Timeout while proxying data.");
            exit(100);
        }
    }

    
    return 0;
}

