#include "logmsg.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#define LOGMSG_BUFLEN       1024

char logmsg_msgbuf[LOGMSG_BUFLEN];
int logmsg_inclpid;         /* true iff process ID has to be prefixed to log msgs */
pid_t logmsg_mypid;         /* if log_prefixpid, then set to the PID of the process */


int logmsg_init(const char *prefix) {
    char *x;

    logprefix = malloc(strlen(prefix)+1);
    strcpy(logprefix, prefix);

    x = getenv("LOGTHRESHOLD");
    if (x != NULL) {
        loglevel = (int)strtol(x, (char **)NULL, 10);
        if (loglevel < 0 || loglevel > 7) {
            loglevel = LOG_ERR;
        }
    } else
        loglevel = LOG_ERR;

    x = getenv("LOGPID");
    if (x != NULL) {
        logmsg_inclpid = 1;
        logmsg_mypid = getpid();
    } else {
        logmsg_inclpid = 0;
    }

    return 0;
}

int logmsg(int prio, char *fmt, ...) {
    va_list ap;

    if (prio > loglevel) return 0;

    /* include Process ID? */
    if (logmsg_inclpid) {
        snprintf(logmsg_msgbuf, LOGMSG_BUFLEN, "(%d) %s%s", logmsg_mypid, logprefix, fmt);
    } else {
        snprintf(logmsg_msgbuf, LOGMSG_BUFLEN, "%s%s", logprefix, fmt);
    }

    if (fmt[strlen(fmt)-1] != '\n') {
        strncat(logmsg_msgbuf, "\n", LOGMSG_BUFLEN);
    }

    va_start(ap, fmt);
    vfprintf(stderr, logmsg_msgbuf, ap);
    va_end(ap);

    return 0;
}

