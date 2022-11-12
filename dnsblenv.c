#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <arpa/nameser.h>
#include <sys/time.h>

/* asynchronous DNS library */
#include <ares.h>

#include "logmsg.h"


/* delay between queries in milliseconds */
#define DELAY_QUERY         300
/* a check for DNS response is checked every this many millisecs */
#define STEP_PERIOD         20

/* maximum number of RBL lists that is possible to configure */
#define MAX_RBLS            20


/* whether the domain has been resolved against any list */
int found = 0;
unsigned int numresponses = 0;

char *clientIP, lookupname[256];

#ifdef CARES14
void dnsresultcallback(void *arg, int status, unsigned char *abuf, int alen);
#else
void dnsresultcallback(void *arg, int status, int timeouts, unsigned char *abuf, int alen);
#endif

int main(int argc, char *argv[]) {
    char *dnsbls;
    char *tok, *toktracer;
    char revIP[16];
    in_addr_t cliaddr;
    ares_channel dnschan;
    unsigned int cnt, numrequests = 0;
    fd_set readfds, writefds;
    int answers[MAX_RBLS];


    if (argc < 2) {
        fprintf(stderr, "Specify the child to run as argument.\n");
        return 110;
    }

    logmsg_init("dnsblenv: ");

    dnsbls = getenv("DNSBL");
    if (dnsbls == NULL) {
        /* pass-through */
        execvp(argv[1], argv+1);
        logmsg(LOG_CRIT, "Unable to exec: %s\n", strerror(errno));
        return 110;
    }

    clientIP = getenv("TCPREMOTEIP");
    if (clientIP == NULL) {
        logmsg(LOG_CRIT, "Unable to fetch remote client address. Terminating.\n");
        return 110;
    }

    /* build hostname to look for */
    cliaddr = inet_addr(clientIP);
    sprintf(revIP, "%d.%d.%d.%d", (cliaddr & 0xFF000000) >> 24, (cliaddr & 0x00FF0000) >> 16, (cliaddr & 0x0000FF00) >> 8, cliaddr & 0x000000FF);

    if (ares_init(& dnschan) != ARES_SUCCESS) {
        logmsg(LOG_ERR, "Unable to open dns channel.\n");
        return 110;
    }

    FD_ZERO(&readfds);
    FD_ZERO(&writefds);

    memset(answers, 0x00, MAX_RBLS);

    toktracer = dnsbls;
    tok = strsep(& toktracer, " ");
    while (tok != NULL && !found && numrequests < MAX_RBLS) {
        numrequests++;

        sprintf(lookupname, "%s.%s", revIP, tok);
        
        logmsg(LOG_DEBUG, "Querying for %s\n", lookupname);

        /* perform DNS lookup */
        ares_query(dnschan, lookupname, ns_c_in, ns_t_a, dnsresultcallback, & answers[numrequests-1]);

        tok = strsep(& toktracer, " ");

        ares_fds(dnschan, &readfds, & writefds);

        /* insert a small delay between queries but poll the status meanwhile */
        cnt = 0;
        do {
            usleep(STEP_PERIOD*1000);
            cnt += STEP_PERIOD;
            ares_process(dnschan, & readfds, & writefds);
        } while (!answers[numrequests-1] && cnt < DELAY_QUERY);
    }
    if (numrequests == MAX_RBLS) {
        logmsg(LOG_CRIT, "Warning! Number of RBLs configured exceeds hardcoded limit (%u)", MAX_RBLS);
        execv(argv[1], argv+1);
        logmsg(LOG_CRIT, "Unable to run %s: %s.\n", argv[1], strerror(errno));
        exit(100);
    }

    /* cleanup uncompleted queries, if any */
    while (numrequests > numresponses) {
        /* insert a small delay between queries */
        usleep(STEP_PERIOD*1000);
        
        ares_fds(dnschan, &readfds, & writefds);
        ares_process(dnschan, & readfds, & writefds);
    }

    ares_destroy(dnschan);
    if (found) {
        char *varname;

        varname = getenv("DNSBL_VARNAME");
        if (varname == NULL) {
            varname = "BLACKLISTED";
        }
        setenv(varname, "", 1);
    }

    execv(argv[1], argv+1);
    logmsg(LOG_CRIT, "Unable to run %s: %s.\n", argv[1], strerror(errno));


    return 0;
}


/* arg is the domain of the list of the lookup */
#ifdef CARES14
void dnsresultcallback(void *arg, int status, unsigned char *abuf, int alen) {
#else
void dnsresultcallback(void *arg, int status, int timeouts, unsigned char *abuf, int alen) {
#endif
    struct hostent *he;
    char *name;
    int i;
    struct in_addr addr;

    /* keep the count of how many SERVERS responded */
    if (*(int *)arg == 0) numresponses++;

    /* increase number of responses for the list answering */
    *(int *)arg += 1;

    switch (status) {
        case ARES_SUCCESS:
            /* address resolved */
            found = 1;
#ifdef CARES14
            if (ares_parse_a_reply(abuf, alen, & he) != ARES_SUCCESS) {
#else
            if (ares_parse_a_reply(abuf, alen, & he, NULL, NULL) != ARES_SUCCESS) {
#endif
                logmsg(LOG_NOTICE, "Unable to parse DNS response\n");
                return;
            }
            for (i = 0, name = he->h_addr_list[0]; name != NULL; i++, name = he->h_addr_list[i]) {
                memcpy(&addr, name, he->h_length);
                logmsg(LOG_INFO, "'%s' listed as '%s'.\n", clientIP, inet_ntoa(addr));
            }
            ares_free_hostent(he);
            break;
        case ARES_ENODATA:
        case ARES_ENOTFOUND:
            /* domain does not exist */
            break;
        default:
            logmsg(LOG_INFO, "Generic error when querying '%s'.\n", (char *)arg);
    }
}

