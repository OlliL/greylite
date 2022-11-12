/*
 * GREYLITE 2.3
 *
 * see http://mij.oltrelinux.com/net/greylite/
 * blame at mij@bitchx.it
 */

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/time.h>
#include <stdlib.h>
#include <sqlite3.h>
#include <regex.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/wait.h>
#include <assert.h>
#ifdef WITH_GEOIP
#include <GeoIP.h>
#endif


#ifndef DEBUG
    /* disable assert()ions */
#   define  NDEBUG
#endif


#include "logmsg.h"

#ifndef MAX
#define MAX(X,Y)        ((X) > (Y) ? (X) : (Y))
#endif


/* timeout in seconds for one read/write operation (seconds) */
#define TIMEOUT                     40
/* big timeout after which exiting (seconds) */
#define BIG_TIMEOUT                 480

/* millisecs to wait when tricking client with greetdelay */
#define GREETDELAY_DEFAULT_DELAY    6000

/* default DB name if DBFILE environment variable is not specified */
#define DBNAME                      "/var/db/greylite/greylite.db"
#ifdef WITH_GEOIP
/* default GeoIP DB name */
#define GEOIPDBNAME                 "/usr/local/share/GeoIP/GeoIP.dat"
#endif
/* cleanup stale entries once every THIS many times */
#define DB_CLEANUP_PERIOD           800
/* cleanup pending entries older than THIS many hours */
#define STALE_PENDING_ENTRIES_PERIOD    18
/* cleanup verified entries older than THIS many hours */
#define STALE_VERIFIED_ENTRIES_PERIOD   480

/* keep this large enough to store any internal-use string */
#define BUFLEN                          1024

#define NETWORK_READ_FD                 0
#define NETWORK_WRITE_FD                1


/* return values for host_delivattempts_threshold() */
#define SUSPICION_DEFAULT_THRESHOLD             1

#define SUSPICION_DISABLED                      -1      /* suspicion is not enabled -- no patterns defined */
#define SUSPICION_HOSTNAME_NOT_AVAILABLE        -2      /* address' PTR is not available (TCPREMOTEHOST env var not present) */
#define SUSPICION_INTERNEALERROR                -3      /* internal error while processing */
#define SUSPICION_NOMATCH                       -4      /* the hostname doesn't match against any rule */

/* return statuses for the rule specification checker -- handle_suspicionrule() */
#define RULESPEC_MATCH                          1       /* specification matched */
#define RULESPEC_NOMATCH                        0       /* specification did not match */
#define RULESPEC_SPECERROR                      -1      /* error in the specification -- incorrect specification */
#define RULESPEC_INTERNALERROR                  -2      /* error while processing -- internal error */

/* rule kinds recognized in the suspicion file */
#define RULE_KIND_GEOIP                         'g'     /* GeoIP country codes */
#define RULE_KIND_REGEX                         'r'     /* regular expressions */
#define RULE_KIND_ENVVAR                        'v'     /* environment variables */    
#define RULE_KIND_CLIBEHAVIOUR                  'b'     /* analysis of the behaviour of the client */
#define RULE_KIND_ENVELOPE                      'e'     /* envelope analysis */

/* result codes for the SMTP envelope session */
#define SMTP_ENVELOPE_SERVERERR                 -2      /* session KO, upstream server responded with an error code (that's been already forwarded to the client) */
#define SMTP_ENVELOPE_INTERNALERR               -1      /* internal error while processing */
#define SMTP_ENVELOPE_OK                        0       /* session OK, envelope data stored correctly */
#define SMTP_ENVELOPE_PROTOERR                  1       /* session KO, recognized protocol error */
#define SMTP_ENVELOPE_WANTAUTH                  2       /* client prompted for authentication */
#define SMTP_ENVELOPE_ENVELINCOMPLETE           3       /* session KO, envelope terminated by DATA command before retrieving (helo,from,to) */
#define SMTP_ENVELOPE_WANTTLS                   4       /* session OK, now switching to encryption */

/* query types */
#define SQLQUERY_ADDR_IN_VERIFIED               0       /* SELECT ip FROM verified WHERE ip = '%s' */
#define SQLQUERY_DELIVERY_ATTEMPTED             1       /* SELECT ip, envsender, envrecipient, attempts FROM pending WHERE ip='%s' AND envsender='%s' AND envrecipient='%s' */


/* maximum command length of SMTP commands */
#define SMTP_MAXCMDLEN                          512

/* data types */
struct envelope_s {
    char helo[SMTP_MAXCMDLEN];
    char from[SMTP_MAXCMDLEN];
    char to[SMTP_MAXCMDLEN];
} envelope;

/* passed to callback for inspecting SQL results from sqlite */
struct sqlret_s {
    int querytype;          /* type of the query whose result is passed */
    union {                 /* possible return types */
        int intval;
    } types;
};

/* bit selectors for client_metainfo.fieldsfilled */
#define METAINFO_HOSTNAME               0x00000001
#define METAINFO_GREETDELAY             0x00000002
#define METAINFO_NUMATTEMPTS            0x00000004
#define METAINFO_RETRIALINTRV           0x00000008
#define METAINFO_NUMPENDINGDELIVS       0x00000010
#define METAINFO_COMMANDERRORS          0x00000020

/* structure holding metainformation on the client -- built incrementally */
struct client_metainfo_s {
    char *address;                          /* IP address of the client as passed by UCSPI */
    char *hostname;                         /* remote host name as passed by UCSPI */
    int greetdelay_trapped;                 /* whether or not the client has sent data before the server's greeting */
    unsigned int numattempts;               /* number of attempts for the current delivery */
    unsigned int retryinterval;             /* time (secs) occurred between first and last deliveries = tslast - tsfirst */
    unsigned int numpendingdelivs;          /* number of deliveries that are pending */
    unsigned int errors;                    /* errors received by the server during the command session: 0 = none, 1 = 4xx codes, 2 = 5xx codes */
    unsigned int fieldsfilled;              /* bitmask telling what fields are ready in the structure */
} client_metainfo = { NULL, NULL, 0, 0, 0, 0, 0, 0};

sqlite3 *db = NULL;                 /* sqlite database */
char buf[BUFLEN];                   /* general purpose buffer. Assume it does not preserve the value after any function call */
char srvresp[BUFLEN];               /* server response buffer. Always holds the last response received by the server */
const char *local_hostname = "localhost";   /* local host name as passed by UCSPI */
int rdp[2] = {0, 0}, wrp[2] = {0, 0};       /* pipes for upstream UCSPI server: greylite --> server AND server --> greylite */


/* db functions */
static int sqcallback(void *userarg, int argc, char *argv[], char **azColName); /* callback for inspecting the result of SELECT queries */
static int busydb_callback(void *userarg, int numattempts);         /* callback for BUSY events on the sqlite db */
void prunedb_pending(void);
void prunedb_verified(void);

/* networking/communication stuff */
int host_delivattempts_threshold(void);             /* returns the number of attempts to be rejected for the current client */
int handle_suspicionrule(char kind, char spec[]);   /* parses and applies suspicion rules */

int do_smtp(void);                                  /* supervises the envelope session btw client and server and compiles the envelope data */
void get_line(int fd, char *string, size_t len);    /* get an envelope command line */
void proxy_data(void);                              /* forward data from/to the upstream server, ignoring it */

void check_greetdelay(unsigned int delay_ms);       /* check whether the client is trapped by greet delay */

void closeall(void);                                /* for atexit(). Closes the db, file descriptors etc */
void sighand(int sig);                              /* signal handler to terminate the program when ALRM is received */

int main(int argc, char *argv[]) {
    char *str;                      /* general purpose char pointer. Assume it never points to a usable buffer */
    int ret;                        /* return values */
    int suspicious;                 /* non-0 if the client is in suspicion list, 0 otherwise */
    struct sqlret_s sqlret;         /* returns int values from SQL queries output */


    /*      STATE:  SANITY-CHECK        */
    /* sanity check */
    if (argc < 2) {
        fprintf(stderr, "Do specify a child to call.\n");
        exit(100);
    }

    logmsg_init("greylite: ");
    signal(SIGALRM, sighand);
    signal(SIGPIPE, sighand);
    alarm(BIG_TIMEOUT);

    /*      STATE:  CHECK-OPERATION     */
    logmsg(LOG_DEBUG, "State: CHECK-OPERATION");

    /* operate or pass? */
    if (getenv("GREYLIST") == NULL) {
        /* do nothing and pass to the upstream server */
        execv(argv[1], argv+1);
        logmsg(LOG_ALERT, "Unable to run %s: %s. Terminating", argv[1], strerror(errno));
        exit(100);
    }


    /*      STATE:  CHECK-VERIFIED-SERVER   */
    logmsg(LOG_DEBUG, "State: CHECK-VERIFIED-SERVER");

    /* fetch local hostname info */
    if ((str = getenv("TCPLOCALHOST")) != NULL) {
        local_hostname = str;
    }
    assert(local_hostname != NULL);

    /* initialize client metainfo structure and fetch remote address info */
    memset(& client_metainfo, 0x00, sizeof(client_metainfo));
    client_metainfo.address = getenv("TCPREMOTEIP");
    if (client_metainfo.address == NULL) {
        logmsg(LOG_CRIT, "Unable to fetch remote host address. Are we running under tcpserver? Terminating.");
        exit(100);
    }
    assert(client_metainfo.address != NULL);

    /* fetch possible custom database file */
    str = getenv("DBFILE");
    if (str != NULL)
        ret = sqlite3_open(str, & db);
    else
        ret = sqlite3_open(DBNAME, & db);

    if (ret != SQLITE_OK) {
        logmsg(LOG_ERR, "Can't open database: %s. Use the DBFILE environment variable! Terminating.", sqlite3_errmsg(db));
        exit(100);
    }

    /* the database is open and we can start operating */
    if (1) {
        struct timeval tp;
        gettimeofday(& tp, NULL);
        srandom((unsigned long)(tp.tv_sec + tp.tv_usec));
    }

    /* close the db when exiting */
    atexit(closeall);
    /* retry with exponential interval when the db is locked */
    sqlite3_busy_handler(db, busydb_callback, NULL);

    /* check if the client IP appears in the verified table */
    sprintf(buf, "SELECT ip FROM verified WHERE ip = '%s'", client_metainfo.address);
    logmsg(LOG_DEBUG, "Query: '%s'", buf);

    sqlret.querytype = SQLQUERY_ADDR_IN_VERIFIED;
    sqlret.types.intval = 0;
    ret = sqlite3_exec(db, buf, sqcallback, &sqlret, &str);
    if (ret != SQLITE_OK) {
        logmsg(LOG_ERR, "Error querying db: %s", str);
        exit(100);
    }

    assert(sqlret.types.intval == 0 || sqlret.types.intval == 1);

    if (sqlret.types.intval) {    /* verified  -=>  pass to the upstream server transparently */
        logmsg(LOG_INFO, "Address '%s' is recognized as a verified server, updating timestamp...", client_metainfo.address);
        sprintf(buf, "UPDATE verified SET ts = DATETIME('now') WHERE ip = '%s'", client_metainfo.address);
        logmsg(LOG_DEBUG, "Query: '%s'", buf);
        ret = sqlite3_exec(db, buf, NULL, NULL, &str);
        sqlite3_close(db);
        execv(argv[1], argv+1);
        logmsg(LOG_CRIT, "Unable to run %s: %s. Terminating", argv[1], strerror(errno));
        exit(100);
    }

    /* attempt with GreetDelay? */
    if ((str = getenv("GREETDELAY")) != NULL) {
        if (sscanf(str, "%u", & ret) != 1) {
            /* the variable did not contain the number of millisecs to delay */
            ret = GREETDELAY_DEFAULT_DELAY;
        }
        check_greetdelay((unsigned int)ret);
    }

    assert(client_metainfo.greetdelay_trapped == 0 || client_metainfo.greetdelay_trapped == 1);

    /*      STATE: VERIF-NEW-PENDING        */
    logmsg(LOG_DEBUG, "State: VERIF-NEW-PENDING");

    /* the client is not verified. It is either sending a first attempt or a
     * re-trial. Call the upstream server and mediate its communication with
     * the client */

    if (pipe(rdp) != 0 || pipe(wrp) != 0) {
        logmsg(LOG_CRIT, "Could not create pipe: %s", strerror(errno));
        exit(100);
    }

    if (fork() == 0) {
        /* run upstream server */
        /* adjust file descriptors */
        if (rdp[0] != NETWORK_READ_FD) {
            dup2(rdp[0], NETWORK_READ_FD);
            close(rdp[0]);
        }
        if (wrp[1] != NETWORK_WRITE_FD) {
            dup2(wrp[1], NETWORK_WRITE_FD);
            close(wrp[1]);
        }
        close(rdp[1]);
        close(wrp[0]);
        /* run the upstream server // UCSPI module */
        execv(argv[1], argv+1);
        logmsg(LOG_CRIT, "Unable to run %s: %s. Terminating", argv[1], strerror(errno));
        exit(100);
    }

    close(rdp[0]);
    close(wrp[1]);


    /* parse the envelope; if the triplet (ip,from,to) is in db, then move to
     * verified, else insert among pending hosts */
    envelope.from[0] = envelope.to[0] = '\0';
    ret = do_smtp();

    switch (ret) {
        /* values that require to close the connection */
        case SMTP_ENVELOPE_PROTOERR:
            /* handshake KO, some error in the protocol */
            close(rdp[1]);
        case SMTP_ENVELOPE_SERVERERR:
            exit(0);
         
        /* values that require to continue the session without greylite's intervention */
        case SMTP_ENVELOPE_INTERNALERR:
            /* handshake KO, some internal processing error */
            /* we failed for some reason, let the main server handle it */
        case SMTP_ENVELOPE_ENVELINCOMPLETE:
            /* DATA command sent before retrieving all of the envelope triple. Pass transparently */
        case SMTP_ENVELOPE_WANTAUTH:
            /* handshake OK, client prompted for authentication, pass transparently */
        case SMTP_ENVELOPE_WANTTLS:
            /* handshake suspended: client and server will negotiate an encrypted session */
            sqlite3_close(db);
            db = NULL;
            proxy_data();
            exit(0);
    }

    /* command session finished properly and we can handle everything */
    assert(ret == 0);

    /* would assert that srvresp is set to the last response from the server instead */

    assert(strlen(envelope.from) > 0 || strlen(envelope.to) > 0);
    logmsg(LOG_INFO, "Envelope (helo,from,to): (%s,%s,%s)", envelope.helo, envelope.from, envelope.to);


    /* we shall certainly write smth in the db now. Probabilistically cleanup stale entries */
    if (random() % DB_CLEANUP_PERIOD == 0) {
        prunedb_pending();
    }

    /* lookup how many times this delivery has been attempted */
    //ret = snprintf(buf, BUFLEN, "SELECT ip, envsender, envrecipient, strftime('%%s','now') - strftime('%%s',tsfirstdelivery), attempts FROM pending WHERE ip='%s' AND envsender='%s' AND envrecipient='%s'", client_metainfo.address, envelope.from, envelope.to);
    ret = snprintf(buf, BUFLEN, "SELECT strftime('%%s','now') - strftime('%%s',tsfirstdelivery), attempts FROM pending WHERE ip='%s' AND envsender='%s' AND envrecipient='%s'", client_metainfo.address, envelope.from, envelope.to);
    if (ret+1 > BUFLEN) {
        /* avoid overrun with injections from envelope session */
        logmsg(LOG_CRIT, "Buffer too small to handle request near line %u: %d bytes needed, %u available. Terminating", __LINE__, ret, BUFLEN);
        exit(100);
    }

    logmsg(LOG_DEBUG, "Query: '%s'", buf);
    sqlret.querytype = SQLQUERY_DELIVERY_ATTEMPTED;
    sqlret.types.intval = 0;
    ret = sqlite3_exec(db, buf, sqcallback, &sqlret, &str);
    if (ret != SQLITE_OK) {
        logmsg(LOG_ERR, "Error querying db: %s", str);
        sqlite3_free(str);
        exit(100);
    }

    assert(client_metainfo.numattempts >= 0);

    logmsg(LOG_INFO, "Metainfo ready: addr(%s) greet(%d) attemptsnum(%u) attemptsintrv(%u) numpendingdelivs(%u) cmderrs(%u)", \
            client_metainfo.address, client_metainfo.greetdelay_trapped, client_metainfo.numattempts, \
            client_metainfo.retryinterval, client_metainfo.numpendingdelivs, client_metainfo.errors);

    /* get the number of retrials expected for this host, against the
     * suspicion file */
    ret = host_delivattempts_threshold();
    if (ret < 0) {
        suspicious = 0;
        switch (ret) {
            case SUSPICION_DISABLED:
            case SUSPICION_HOSTNAME_NOT_AVAILABLE:
            case SUSPICION_INTERNEALERROR:
            case SUSPICION_NOMATCH:
                ret = SUSPICION_DEFAULT_THRESHOLD;
                break;
            default:
                logmsg(LOG_CRIT, "unknown return value from host_delivattempts_threshold(): %d", ret);
                break;
        }
    } else {
        suspicious = 1;
    }

    assert(suspicious == 0 || suspicious == 1);
        
    logmsg(LOG_INFO, "%shost '%s' requires %u re-attempts, %u have been done.", (suspicious ? "suspicious " : ""), client_metainfo.address, ret, client_metainfo.numattempts);

    if (client_metainfo.numattempts >= (unsigned int)ret) {
        /* this delivery has been attempted in the past and can now be passed */

        if (! suspicious) {
            /*          STATE:  PENDING-VERIFIED        */
            logmsg(LOG_DEBUG, "State: PENDING-VERIFIED");

            /* then move from pending to verified, then accept */
            sprintf(buf, "INSERT INTO verified (ip,ts) VALUES ('%s', DATETIME('NOW'))", client_metainfo.address);
            logmsg(LOG_DEBUG, "Query: '%s'", buf);
            ret = sqlite3_exec(db, buf, NULL, NULL, &str);
            if (ret != SQLITE_OK) {
                logmsg(LOG_ERR, "Query failed: '%s' -- '%s'", buf, str);
                exit(100);
            }

            /* probabilistically prune verified entries older than STALE_PENDING_ENTRIES_PERIOD hours ago */
            /* do this approximately once every 15 new insertions */
            if (random() % 15 == 0) {
                prunedb_verified();
            }

            /* clear all suspended messages from this sender */
            sprintf(buf, "DELETE FROM pending WHERE ip='%s'", client_metainfo.address);
        } else {
            /*          STATE:  PENDING-PASSED          */
            logmsg(LOG_DEBUG, "State: PENDING-SUSPICIOUS-PASSED");

            /* clear the entry for this message */
            ret = snprintf(buf, BUFLEN, "DELETE FROM pending WHERE ip='%s' AND envsender='%s' AND envrecipient='%s'", client_metainfo.address, envelope.from, envelope.to);
            if (ret+1 > BUFLEN) {
                /* avoid overrun with injections from envelope session */
                logmsg(LOG_CRIT, "Buffer too small to handle request near line %u: %d bytes needed, %u available. Terminating", __LINE__, ret, BUFLEN);
                exit(100);
            }
        }

        assert(strlen(buf) > 0 && strstr(buf, "DELETE") == buf);

        /* run the query previously built -- either for the suspicious or not
         * suspicion case */
        if (client_metainfo.numattempts > 0) {
            logmsg(LOG_DEBUG, "Query: '%s'", buf);
            ret = sqlite3_exec(db, buf, NULL, NULL, &str);
            if (ret != SQLITE_OK) {
                logmsg(LOG_ERR, "Query failed: '%s' -- '%s'", buf, str);
                exit(100);
            }
        }

        sqlite3_close(db);
        db = NULL;

        assert(strlen(srvresp) > strlen("200\r\n") && strlen(srvresp) < sizeof(srvresp));

        /* restore the last server message suspended */
        write(NETWORK_WRITE_FD, srvresp, strlen(srvresp));

        /* let the client and the server go on with the session */
        proxy_data();
    } else {
        /* entry below the threshold, insert/update it to the new attempt number */

        /* spare resources: terminate connections with server and client first */
        close(rdp[1]);

        /* use temporary error 452 (insuff storage) to distinguish from the
         * usual greylisting response that spammers may act upon */
        if (random() % 2)
            sprintf(buf, "452 insufficient system storage\r\n");
        else
            sprintf(buf, "451 qqt failure (#4.3.0)\r\n");
        write(NETWORK_WRITE_FD, buf, strlen(buf));
        close(NETWORK_WRITE_FD);

        /* then update DB */
        if (client_metainfo.numattempts == 0) {
            /*          STATE:  NEW-ENTRY               */
            logmsg(LOG_DEBUG, "State: NEW-ENTRY");
            /* then insert as pending to-be-verified, then reject */
            ret = snprintf(buf, BUFLEN, "INSERT INTO pending (ip, envsender, envrecipient, tsfirstdelivery, tslastdelivery, attempts) VALUES ('%s','%s','%s',DATETIME('NOW'),DATETIME('NOW'),1)", client_metainfo.address, envelope.from, envelope.to);
            if (ret+1 > BUFLEN) {
                /* avoid overrun with injections from envelope session */
                logmsg(LOG_CRIT, "Buffer too small to handle request near line %u: %d bytes needed, %u available. Terminating", __LINE__, ret, BUFLEN);
                exit(100);
            }
        } else {
            /*          STATE:  UPDATE-ENTRY               */
            logmsg(LOG_DEBUG, "State: UPDATE-ENTRY");
            /* increment the number of attempts in the current entry */
            ret = snprintf(buf, BUFLEN, "UPDATE pending SET attempts=(SELECT attempts FROM pending WHERE ip='%s' AND envsender='%s' AND envrecipient='%s' LIMIT 1)+1, tslastdelivery=DATETIME('now') WHERE ip='%s' AND envsender='%s' AND envrecipient='%s'", client_metainfo.address, envelope.from, envelope.to, client_metainfo.address, envelope.from, envelope.to);
            if (ret+1 > BUFLEN) {
                /* avoid overrun with injections from envelope session */
                logmsg(LOG_CRIT, "Buffer too small to handle request near line %u: %d bytes needed, %u available. Terminating", __LINE__, ret, BUFLEN);
                exit(100);
            }
        }

        assert((client_metainfo.numattempts == 0 && strstr(buf, "INSERT") == buf) || (client_metainfo.numattempts != 0 && strstr(buf, "UPDATE") == buf));

        /* run the query previously built -- either for new entry or for updating */
        logmsg(LOG_DEBUG, "Query: %s", buf);
        ret = sqlite3_exec(db, buf, NULL, NULL, &str);
        if (ret != SQLITE_OK) {
            logmsg(LOG_ERR, "Query failed: '%s' -- '%s'", buf, str);
            exit(100);
        }
    }

    return 0;
}

/* returns the number of attempts to be rejected for the current client */
int host_delivattempts_threshold(void) {
    char *suspfilename;
    char rule[BUFLEN];
    FILE *sfile;
    char rulekind;
    unsigned int attempts, lineno = 0;
    int ret;


    /* is suspicion enabled? */
    suspfilename = getenv("SUSPICION");
    if (suspfilename == NULL) {
        logmsg(LOG_DEBUG, "Suspicion is not enabled.");
        return SUSPICION_DISABLED;
    }

    /* open suspicion file */
    sfile = fopen(suspfilename, "r");
    if (sfile == NULL) {
        logmsg(LOG_CRIT, "Unable to open suspicion file '%s': %s", suspfilename, strerror(errno));
        return SUSPICION_INTERNEALERROR;
    }

    /* attempting to fetch the client PTR name */
    client_metainfo.hostname = getenv("TCPREMOTEHOST");
    client_metainfo.fieldsfilled |= METAINFO_HOSTNAME;

    /* checking the remote hostname against the RE patterns provided, one per
     * line. The first matching line wins. Each line is formatted like:
     *      "threshold <whitespace> re_pattern"
     * if re_pattern matches the remote hostname, threshold is returned
     */
    while (fgets(buf, BUFLEN, sfile) != NULL) {
        lineno++;
        /* skip line? */
        if (buf[0] == '#') continue;
        /* buffer exceeded? */
        if (buf[strlen(buf)-1] != '\n') {
            logmsg(LOG_CRIT, "Line %u too long (max is %u) in suspicion file '%s', skipping.", lineno, BUFLEN, suspfilename);
            /* flush current line */
            while (fgets(buf, BUFLEN, sfile) != NULL  &&  buf[strlen(buf)-1] != '\n');
            continue;
        }
        buf[strlen(buf)-1] = '\0';
        if (sscanf(buf, "%u %c ", & attempts, & rulekind) != 2) {
            logmsg(LOG_ERR, "Unable to parse line %u, expected \"number kind rule\", skipping.", lineno);
            continue;
        }
        /* copy the rest of the string into "rule" */
        sprintf(rule, "%u", attempts);
        strcpy(rule, buf + strlen(rule) + 3 /* strlen(" X ") */);
        logmsg(LOG_DEBUG, "Read line %u from suspicion file; checking against rule '%s'", lineno, rule);

        if (rule[0] == '!') {
            /* NOT rule */
            ret = handle_suspicionrule(rulekind, rule+2);
            if (ret >= 0)
                ret = ! ret;
        } else {
            /* plain rule */
            ret = handle_suspicionrule(rulekind, rule);
        }

        assert(ret == RULESPEC_MATCH || ret == RULESPEC_NOMATCH || ret == RULESPEC_SPECERROR || ret == RULESPEC_INTERNALERROR);

        switch (ret) {
            case RULESPEC_MATCH:     /* rule matched */
                logmsg(LOG_NOTICE, "Rule '%c' in line %u matched client '%s', returning %u attempts.", rulekind, lineno, client_metainfo.address, attempts);
                fclose(sfile);
                return attempts;
            case RULESPEC_NOMATCH:     /* rule did not match */
                logmsg(LOG_DEBUG, "Rule '%c' in line %u did not match.", rulekind, lineno);
                continue;
                break;
            case RULESPEC_SPECERROR:    /* error in rule */
                logmsg(LOG_ERR, "Error in rule specification in line %u, skipping...", lineno);
                continue;
                break;
            case RULESPEC_INTERNALERROR:    /* error while processing rule */
                logmsg(LOG_ERR, "Error while processing rule in line %u, skipping...", lineno);
                break;
        }
    }

    fclose(sfile);

    logmsg(LOG_INFO, "Address '%s' did not match any rule.", client_metainfo.address);
    return SUSPICION_NOMATCH;
}


/* return values: see RULESPEC_* defined */
int handle_suspicionrule(char kind, char spec[]) {
    regex_t re;
    char *tok, *toktracer;      /* used for string tokenization */
#ifdef WITH_GEOIP
    GeoIP *gidb = NULL;
    char *geoipdb_file;
    const char *country;
#endif

    switch (kind) {
        case RULE_KIND_REGEX:   /* regular expression spec */
            /* fetch remote hostname from UCSPI */
            if (client_metainfo.hostname == NULL) {
                logmsg(LOG_INFO, "Unable to get PTR for address '%s'.", client_metainfo.address);
                return RULESPEC_INTERNALERROR;
            }
            /* 
             * suspicion lines of REGEX kind are like this:
             *      4 r [^a-zA-Z](dynamic|ppp)[^a-zA-Z]
             */
            logmsg(LOG_DEBUG, "Processing spec of kind REGEX.");
            if (regcomp(& re, spec, REG_EXTENDED | REG_ICASE) != 0) {
                logmsg(LOG_ERR, "Unable to compile regular expression \"%s\", skipping.", spec);
                return RULESPEC_SPECERROR;
            }

            if (regexec(& re, client_metainfo.hostname, 0, NULL, 0) == 0) {
                regfree(& re);
                logmsg(LOG_INFO, "Address '%s' ('%s') matched REGEX spec.", client_metainfo.address, client_metainfo.hostname);
                return RULESPEC_MATCH;
            }

            regfree(& re);
            break;
#ifdef WITH_GEOIP
        case RULE_KIND_GEOIP:   /* GeoIP spec */
            /* 
             * suspicion lines of kind GeoIP are like this:
             *      4 g TW CN KR HK MY US
             */
            logmsg(LOG_DEBUG, "Processing spec of kind GEOIP.");
            if (gidb == NULL) {             /* is DB open? */
                /* open geoip database */
                geoipdb_file = getenv("GEOIPDB_FILE");
                if (geoipdb_file == NULL) geoipdb_file = GEOIPDBNAME;
                logmsg(LOG_DEBUG, "Opening GeoIP db file '%s'", geoipdb_file);
                gidb = GeoIP_open(geoipdb_file, GEOIP_STANDARD);
                if (gidb == NULL) {
                    logmsg(LOG_ERR, "Unable to open GeoIP database '%s'.", geoipdb_file);
                    return RULESPEC_INTERNALERROR;
                }
            }
            country = GeoIP_country_code_by_addr(gidb, client_metainfo.address);
            if (country == NULL) {
                logmsg(LOG_DEBUG, "Unable to fetch country for address '%s'.", client_metainfo.address);
                return RULESPEC_INTERNALERROR;
            }
            toktracer = spec;
            tok = strsep(& toktracer, " ,");
            while (tok != NULL) {
                if (strcmp(country, tok) == 0) {
                    logmsg(LOG_INFO, "Address '%s' matched GEOIP spec, country '%s'.", client_metainfo.address, tok);
                    /* GeoIP_close(gidb); */
                    return RULESPEC_MATCH;
                }
                tok = strsep(& toktracer, " ,");
            }
            break;
#endif
        case RULE_KIND_ENVVAR:
            /*
             * suspicion lines of kind ENVVAR are like this:
             *      4 v MYVERYOWNVAR
             */
            toktracer = spec;
            tok = strsep(& toktracer, " ,");
            while (tok != NULL) {
                /* tmpstr = environment variable to look for */
                char *tmpstr = getenv(tok);
                if (tmpstr != NULL) {
                    logmsg(LOG_INFO, "Address '%s' matched ENVVAR spec, variable %s.", client_metainfo.address, tok);
                    return RULESPEC_MATCH;
                }
                tok = strsep(& toktracer, " ,");
            }
            break;
        case RULE_KIND_CLIBEHAVIOUR:
            /*
             * suspicion lines of kind CLIBEHAVIOUR are like this:
             *      100 b retryinterval greetdelay
             */
            toktracer = spec;
            tok = strsep(& toktracer, " ,");
            while (tok != NULL) {
                if (strcmp(tok, "greetdelay") == 0) {                   /* greet delay */
                    if (! (client_metainfo.fieldsfilled & METAINFO_GREETDELAY)) {
                        logmsg(LOG_ERR, "Unable to inspect BEHAVIOUR spec's block greetdelay: GREETDELAY env var not set, greetdelay not attempted.");
                        tok = strsep(& toktracer, " ,");
                        continue;
                    }
                    if (client_metainfo.greetdelay_trapped) {
                        logmsg(LOG_INFO, "Address '%s' matched CLIBEHAVIOUR spec, type 'greetdelay'.", client_metainfo.address);
                        return RULESPEC_MATCH;
                    }
                } else if (strcmp(tok, "retryinterval") == 0) {         /* retrial interval */
                    unsigned int mindelay;

                    switch (client_metainfo.numattempts) {
                        case 0: mindelay = 0;       break;
                        case 1: mindelay = 20;      break;
                        case 2: mindelay = 200;     break;
                        default: mindelay = 500*(client_metainfo.numattempts - 2);
                    }

                    if (client_metainfo.retryinterval < mindelay) {
                        logmsg(LOG_INFO, "Address '%s' matched CLIBEHAVIOUR spec, type 'retryinterval' (%u<%u).", client_metainfo.address, client_metainfo.retryinterval, mindelay);
                        return RULESPEC_MATCH;
                    }
                } else if (strcmp(tok, "commanderrors") == 0) {           /* errors in the command session */
                    switch (client_metainfo.errors) {
                        case 0:     /* no errors */
                            break;
                        case 1:     /* temporary errors (SMTP 4xx codes) */
                        case 2:     /* permanent errors (SMTP 5xx codes) */
                            logmsg(LOG_DEBUG, "Address '%s' matched CLIBEHAVIOUR spec, type 'commanderrors' (%u).", client_metainfo.address, client_metainfo.errors);
                            return RULESPEC_MATCH;
                            break;
                        default:    /* ? */
                            logmsg(LOG_NOTICE, "Address '%s' reached an unknown error state: %u", client_metainfo.errors);
                    }
                } else {                                                /* unknown behaviour */
                    logmsg(LOG_ERR, "Behaviour spec '%s' not recognized.", tok);
                    return RULESPEC_SPECERROR;
                }

                tok = strsep(& toktracer, " ,");
            }
            break;
        case RULE_KIND_ENVELOPE:
            /*
             * suspicion lines of kind ENVELOPE are like this:
             *      0 e s:^my@re[gex].c(om)?$ r:@domain.net$ h:fakeh(el|os)
             */
            toktracer = spec;
            tok = strsep(& toktracer, " ,");
            while (tok != NULL) {
                /* sanity check */
                if (tok[0] == '\0' || tok[1] != ':' || tok[2] == '\0') {
                    logmsg(LOG_ERR, "Unrecognized block in ENVELOPE spec.");
                    tok = strsep(& toktracer, " ,");
                    return RULESPEC_SPECERROR;
                }
                if (regcomp(& re, tok+2, REG_EXTENDED) != 0) {     /* error compiling spec's regex */
                    logmsg(LOG_ERR, "Unable to compile sender regex '%s', skipping.", tok+2);
                    tok = strsep(& toktracer, " ,");
                    return RULESPEC_SPECERROR;
                }
                /* spec successfully compiled, inspect what it should match */
                switch (tok[0]) {
                    case 's':       /* match sender */
                        if (regexec(& re, envelope.from, 0, NULL, 0) == 0) {
                            logmsg(LOG_INFO, "Sender '%s' matched ENVELOPE spec '%s'.", envelope.from, tok);
                            regfree(& re);
                            return RULESPEC_MATCH;
                        }
                        break;
                    case 'r':       /* match recipient */
                        if (regexec(& re, envelope.to, 0, NULL, 0) == 0) {
                            logmsg(LOG_INFO, "Recipient '%s' matched ENVELOPE spec '%s'.", envelope.to, tok);
                            regfree(& re);
                            return RULESPEC_MATCH;
                        }
                        break;
                    case 'h':
                        if (regexec(& re, envelope.helo, 0, NULL, 0) == 0) {
                            logmsg(LOG_INFO, "Helo msg '%s' matched ENVELOPE spec '%s'.", envelope.helo, tok);
                            regfree(& re);
                            return RULESPEC_MATCH;
                        }
                        break;
                    default:
                        logmsg(LOG_ERR, "Unrecognized qualifier '%c' for ENVELOPE spec.", tok[0]);
                        return RULESPEC_SPECERROR;
                }

                regfree(& re);
                tok = strsep(& toktracer, " ,");
            }
            break;
        default:
            logmsg(LOG_ERR, "spec kind %c is not supported in suspicion file.", kind);
            return RULESPEC_SPECERROR;
    }
    
    /* no match */
    return RULESPEC_NOMATCH;
}

/* see error codes SMTP_ENVELOPE_* above */
int do_smtp() {
    unsigned int i, len;
    char clicmd[BUFLEN];
    regex_t helo, ehlo, mailfrom, rcptto, email, data, rset, auth, starttls, quit;
#define RE_MAXMATCHES   5
    regmatch_t submatches[RE_MAXMATCHES];


    /* compile regular expressions */
    if (regcomp(&helo, "^helo[[:space:]]+([^'[:space:]]+)[[:space:]]*$", REG_ICASE | REG_EXTENDED) != 0) {
        logmsg(LOG_CRIT, "Unable to compile HELO regular expression");
        return SMTP_ENVELOPE_INTERNALERR;
    }
    if (regcomp(&ehlo, "^ehlo[[:space:]]+([^'[:space:]]+)[[:space:]]*$", REG_ICASE | REG_EXTENDED) != 0) {
        logmsg(LOG_CRIT, "Unable to compile EHLO regular expression");
        return SMTP_ENVELOPE_INTERNALERR;
    }
    if (regcomp(&mailfrom, "^mail[[:space:]]+from:", REG_ICASE | REG_EXTENDED) != 0) {
        logmsg(LOG_CRIT, "Unable to compile MAIL FROM regular expression");
        return SMTP_ENVELOPE_INTERNALERR;
    }
    if (regcomp(&rcptto, "^rcpt[[:space:]]+to:", REG_ICASE | REG_EXTENDED) != 0) {
        logmsg(LOG_CRIT, "Unable to compile RCPT TO regular expression");
        return SMTP_ENVELOPE_INTERNALERR;
    }
    if (regcomp(&email, "([-&*+./0-9=?a-zA-Z^_{}~]+@([-a-zA-Z0-9_]+\\.)*[a-zA-Z0-9]+)", REG_ICASE | REG_EXTENDED) != 0) {
        logmsg(LOG_CRIT, "Unable to compile email regular expression");
        return SMTP_ENVELOPE_INTERNALERR;
    }
    if (regcomp(&data, "^data", REG_ICASE | REG_EXTENDED) != 0) {
        logmsg(LOG_CRIT, "Unable to compile DATA regular expression");
        return SMTP_ENVELOPE_INTERNALERR;
    }
    if (regcomp(&rset, "^rset", REG_ICASE | REG_EXTENDED) != 0) {
        logmsg(LOG_CRIT, "Unable to compile RSET regular expression");
        return SMTP_ENVELOPE_INTERNALERR;
    }
    if (regcomp(&auth, "^auth ", REG_ICASE | REG_EXTENDED) != 0) {
        logmsg(LOG_CRIT, "Unable to compile AUTH regular expression");
        return SMTP_ENVELOPE_INTERNALERR;
    }
    if (regcomp(&starttls, "^starttls", REG_ICASE | REG_EXTENDED) != 0) {
        logmsg(LOG_CRIT, "Unable to compile STARTTLS regular expression");
        return SMTP_ENVELOPE_INTERNALERR;
    }
    if (regcomp(&quit, "^quit", REG_ICASE | REG_EXTENDED) != 0) {
        logmsg(LOG_CRIT, "Unable to compile QUIT regular expression");
        return SMTP_ENVELOPE_INTERNALERR;
    }

    client_metainfo.errors = 0;
    client_metainfo.fieldsfilled |= METAINFO_COMMANDERRORS;

    /* fetching (& forwarding) the server's greeting */
    logmsg(LOG_DEBUG, "Expecting server greeting...");
    get_line(wrp[0], srvresp, BUFLEN);
    write(NETWORK_WRITE_FD, srvresp, strlen(srvresp));
    logmsg(LOG_DEBUG, "Got message from server: '%s'", srvresp);

    /* handle greeting errors */
    if (srvresp[0] == '4' || srvresp[0] == '5') {
        logmsg(LOG_NOTICE, "\"Service unavailable\" from the upstream server (closing connection): '%s'.", srvresp);
        exit(0);
    }

    /* begin command session: client commands, server responds */
    do {
        /* expect command from client */
        get_line(NETWORK_READ_FD, clicmd, BUFLEN);
        logmsg(LOG_DEBUG, "Got message from client: '%s'", clicmd);
        write(rdp[1], clicmd, strlen(clicmd));

        /* fetch response from server */
        get_line(wrp[0], srvresp, BUFLEN);
        logmsg(LOG_DEBUG, "Got message from server: '%s'", srvresp);

       
        /* error from the upstream server? */
        if (srvresp[0] == '4' || srvresp[0] == '5') {
            logmsg(LOG_INFO, "Error from the upstream server: '%s'.", srvresp);
            client_metainfo.errors = (srvresp[0] == '4' ? 1 : 2);
            /* forward & ignore commands resulting in some error on the server */
            write(NETWORK_WRITE_FD, srvresp, strlen(srvresp));
            continue;
        }

        /* analyze client command */
        if (regexec(& helo, clicmd, RE_MAXMATCHES, submatches, 0) == 0) {                /* HELO */
            len = submatches[1].rm_eo - submatches[1].rm_so;
            if (len >= SMTP_MAXCMDLEN) {
                logmsg(LOG_ERR, "Maximum command length (%d >= %d) exceeded ('%s')! Closing connection.", len, SMTP_MAXCMDLEN, clicmd);
                exit(100);
            }
            for (i = 0; i < len; i++) envelope.helo[i] = clicmd[i + submatches[1].rm_so];
            envelope.helo[len] = '\0';
            logmsg(LOG_DEBUG, "Got HELO command '%s'", envelope.helo);
        } else if (regexec(& ehlo, clicmd, RE_MAXMATCHES, submatches, 0) == 0) {         /* EHLO */
            len = submatches[1].rm_eo - submatches[1].rm_so;
            if (len >= SMTP_MAXCMDLEN) {
                logmsg(LOG_ERR, "Maximum command length (%d >= %d) exceeded ('%s')! Closing connection.", len, SMTP_MAXCMDLEN, clicmd);
                exit(100);
            }
            for (i = 0; i < len; i++) envelope.helo[i] = clicmd[i + submatches[1].rm_so];
            envelope.helo[len] = '\0';
            logmsg(LOG_DEBUG, "Got EHLO command '%s'", envelope.helo);
        } else if (regexec(& mailfrom, clicmd, 0, NULL, 0) == 0) {                       /* MAIL FROM */
            if (regexec(& email, clicmd, RE_MAXMATCHES, submatches, 0) == 0) {
                len = submatches[1].rm_eo - submatches[1].rm_so;
                if (len >= SMTP_MAXCMDLEN) {
                    logmsg(LOG_ERR, "Maximum command length (%d >= %d) exceeded ('%s')! Closing connection.", len, SMTP_MAXCMDLEN, clicmd);
                    exit(100);
                }
                for (i = 0; i < len; i++) envelope.from[i] = clicmd[i + submatches[1].rm_so];
            } else if (strstr(clicmd, "<>") != NULL) {
                len = 0;
            } else {
                logmsg(LOG_NOTICE, "Syntax error in MAIL FROM command, cannot extract email from '%s'.", clicmd);
                continue;
            }
            envelope.from[len] = '\0';
            logmsg(LOG_DEBUG, "Got MAIL FROM command '%s'", envelope.from);
        } else if (regexec(& rcptto, clicmd, 0, NULL, 0) == 0) {                        /* RCPT TO */
            if (regexec(& email, clicmd, RE_MAXMATCHES, submatches, 0) == 0) {
                len = submatches[0].rm_eo - submatches[0].rm_so;
                if (len >= SMTP_MAXCMDLEN) {
                    logmsg(LOG_ERR, "Maximum command length (%d >= %d) exceeded ('%s')! Closing connection.", len, SMTP_MAXCMDLEN, clicmd);
                    exit(100);
                }
                for (i = 0; i < len; i++) envelope.to[i] = clicmd[i + submatches[1].rm_so];
            } else if (strstr(clicmd, "<>") != NULL) {
                len = 0;
            } else {
                logmsg(LOG_NOTICE, "Syntax error in RCPT TO command, cannot extract email from '%s'.", clicmd);
                continue;
            }
            envelope.to[len] = '\0';
            logmsg(LOG_DEBUG, "Got RCPT TO command '%s'", envelope.to);

            /* envelope complete? */
            if (envelope.helo != NULL && envelope.from != NULL && envelope.to != NULL) {
                regfree(& helo);
                regfree(& ehlo);
                regfree(& mailfrom);
                regfree(& rcptto);
                regfree(& data);
                regfree(& rset);
                regfree(& auth);
                regfree(& starttls);
                regfree(& quit);
                return SMTP_ENVELOPE_OK;
            }
            /* otherwise go on with the session */
        } else if (regexec(& data, clicmd, 0, NULL, 0) == 0) {         /* DATA */
            logmsg(LOG_DEBUG, "DATA command, terminating envelope session.");
            /* envelope terminated, return value */
            regfree(& helo);
            regfree(& ehlo);
            regfree(& mailfrom);
            regfree(& rcptto);
            regfree(& data);
            regfree(& rset);
            regfree(& auth);
            regfree(& starttls);
            regfree(& quit);
            write(NETWORK_WRITE_FD, srvresp, strlen(srvresp));
            return SMTP_ENVELOPE_ENVELINCOMPLETE;
        } else if (regexec(& auth, clicmd, 0, NULL, 0) == 0) {                           /* AUTH */
            /* pass authentication session to the server */
            regfree(& helo);
            regfree(& ehlo);
            regfree(& mailfrom);
            regfree(& rcptto);
            regfree(& data);
            regfree(& rset);
            regfree(& auth);
            regfree(& starttls);
            regfree(& quit);
            write(NETWORK_WRITE_FD, srvresp, strlen(srvresp));
            return SMTP_ENVELOPE_WANTAUTH;
        } else if (regexec(& starttls, clicmd, 0, NULL, 0) == 0) {                       /* STARTTLS */
            /* client wants to start an encrypted session (and server accepted) */
            regfree(& helo);
            regfree(& ehlo);
            regfree(& mailfrom);
            regfree(& rcptto);
            regfree(& data);
            regfree(& rset);
            regfree(& auth);
            regfree(& starttls);
            regfree(& quit);
            write(NETWORK_WRITE_FD, srvresp, strlen(srvresp));
            return SMTP_ENVELOPE_WANTTLS;
        } else if (regexec(& quit, clicmd, 0, NULL, 0) == 0) {                           /* QUIT */
            /* client wants to terminate session */
            logmsg(LOG_DEBUG, "QUIT command, terminating connection.");
            i = snprintf(clicmd, BUFLEN, "221 %s\r\n", local_hostname);
            if (i+1 > BUFLEN) {
                /* avoid overrun with injections from envelope session */
                logmsg(LOG_CRIT, "Buffer too small to handle request near line %u: %d bytes needed, %u available. Terminating", __LINE__, i, BUFLEN);
                exit(100);
            }
            write(NETWORK_WRITE_FD, srvresp, strlen(srvresp));
            exit(0);
        } else if (regexec(& rset, clicmd, 0, NULL, 0) == 0) {                           /* RSET */
            envelope.helo[0] = '\0';
            envelope.from[0] = '\0';
            envelope.to[0] = '\0';
        } else {                                                                        /* UNKNOWN / UNSUPPORTED */
            logmsg(LOG_INFO, "Got unsupported message '%s'", clicmd);
        }

        /* forward server response to the client */
        write(NETWORK_WRITE_FD, srvresp, strlen(srvresp));
        /* continue if server sent "250-" */
        while (srvresp[0] == '2' && srvresp[1] == '5' && srvresp[2] == '0' && srvresp[3] == '-') {
            get_line(wrp[0], srvresp, BUFLEN);
            logmsg(LOG_DEBUG, "Got message from server: '%s'", srvresp);
            write(NETWORK_WRITE_FD, srvresp, strlen(srvresp));
        }
    } while (1);
}

void get_line(int fd, char *string, size_t len) {
    int ret;
    size_t cnt;
    int oldfl;
    struct pollfd fds[1];


    assert(string != NULL && len > 0);

    oldfl = fcntl(fd, F_GETFL, 0);
    if (oldfl == -1) {
        logmsg(LOG_ERR, "Cannot get attributes for fd %d", fd);
        exit(100);
    }
    fcntl(fd, F_SETFL, oldfl | O_NONBLOCK);

    fds[0].fd = fd;
    fds[0].events = POLLIN;

    cnt = 0;

    do {
        ret = read(fd, &string[cnt], 1);
        if (ret == 0 && errno != EAGAIN)  {
            logmsg(LOG_INFO, "Client '%s' dropped the connection.", client_metainfo.address, strerror(errno)); 
            exit(100);
        } else if (ret < 0) {
            if (errno != EAGAIN) {
                /* error or timeout */
                logmsg(LOG_ERR, "Error in read(): %s", strerror(errno));
                exit(100);
            }
            /* no data was available, poll() for some */
            ret = poll(fds, 1, TIMEOUT*1000);
        } else
            cnt++;
    } while (ret > 0 && string[cnt-1] != '\n' && len > cnt+1);
    if (ret <= 0) {
        /* poll() error or timeout */
        logmsg(LOG_INFO, "Read timeout reached for socket %d, client %s", fd, client_metainfo.address);
        exit(100);
    } else if (cnt >= len) {
        logmsg(LOG_CRIT, "Buffer too small to handle request near line %u: %d bytes needed, %u available. Terminating", __LINE__, cnt, BUFLEN);
        exit(100);
    }
    string[cnt] = '\0';

    fcntl(fd, F_SETFL, oldfl);

    assert(strlen(string) < len || string[strlen(string)-1] == '\n');
}

/* check the client against the greet delay trap */
void check_greetdelay(unsigned int delay_ms) {
    struct pollfd fds[1];

    assert(delay_ms > 0);

    fds[0].fd = NETWORK_READ_FD;
    fds[0].events = POLLIN;

    switch (poll(fds, 1, delay_ms + (random() % delay_ms))) {
        case -1:    /* poll() error */
            logmsg(LOG_ERR, "poll() failed when tricking client with greetdelay.");
        case 0:     /* client not trapped */
            logmsg(LOG_DEBUG, "greetdelay trap: not caught.");
            client_metainfo.greetdelay_trapped = 0;
            break;
        default:    /* client trapped */
            logmsg(LOG_DEBUG, "greetdelay trap: caught.");
            client_metainfo.greetdelay_trapped = 1;
    }
    client_metainfo.fieldsfilled |= METAINFO_GREETDELAY;
}

void proxy_data(void) {
    struct pollfd fds[2];
    int ret, len;

    fcntl(NETWORK_READ_FD, F_SETFL, O_NONBLOCK);
    fcntl(wrp[0], F_SETFL, O_NONBLOCK);

    fds[0].fd = NETWORK_READ_FD;
    fds[0].events = POLLIN;

    fds[1].fd = wrp[0];
    fds[1].events = POLLIN;

    while ((ret = poll(fds, 2, TIMEOUT*1000)) != -1) {
        /* data to read */
        if (fds[0].revents & POLLIN) {
            /* client ---> server */
            len = read(NETWORK_READ_FD, buf, BUFLEN);
            if (len <= 0) exit(0);
            if (write(rdp[1], buf, len) != len) {
                logmsg(LOG_ERR, "Unable to write to the server %d bytes: %s.", len, strerror(errno));
                /* rdp[0] = rdp[1] = 0; */
                exit(0);
            }
        } else if (fds[1].revents & POLLIN) {
            /* server ---> client */
            len = read(wrp[0], buf, BUFLEN);
            if (len <= 0) exit(0);
            if (write(NETWORK_WRITE_FD, buf, len) != len) {
                logmsg(LOG_ERR, "Unable to write to the client %d bytes: %s.", len, strerror(errno));
                exit(0);
            }
        } else {
            int status;

            logmsg(LOG_INFO, "Timeout while reading from network (%d:%hd:%hd).", ret, fds[0].revents, fds[1].revents);
            /* possibly collect child exit status */
            ret = waitpid(-1, & status, WNOHANG);
            if (ret != -1) {
                if (WIFEXITED(status)) {
                    logmsg(LOG_DEBUG, "Child exited, status %d.", WEXITSTATUS(status));
                } else {
                    logmsg(LOG_DEBUG, "Child terminated, signal %d.", WTERMSIG(status));
                }
            }
            exit(100);
        }
    }

    exit(0);
}

static int sqcallback(void *userarg, int argc, char *argv[], char **azColName) {
    struct sqlret_s *sqlr;


    assert(userarg != NULL);
    if (userarg == NULL) {
        logmsg(LOG_ERR, "sqcallback called unexpectedly! Forcibly terminating the query.");
        return -1;
    }

    sqlr = (struct sqlret_s *)userarg;
    switch (sqlr->querytype) {
        case SQLQUERY_ADDR_IN_VERIFIED:
            /* Query was:       "SELECT ip FROM verified WHERE ip = '%s'"       */
            assert(argc == 1 && strlen(argv[0]));
            logmsg(LOG_DEBUG, "Query-AddrInVerified: %s found amidst verified servers", argv[0]);
            sqlr->types.intval = 1;
            break;
        case SQLQUERY_DELIVERY_ATTEMPTED:
            /* Query was:       "SELECT strftime('%%s','now') - strftime('%%s',tsfirstdelivery), attempts FROM pending WHERE ip='%s' AND envsender='%s' AND envrecipient='%s'"         */
            assert(argc == 2 && strlen(argv[0]) > 0 && strlen(argv[1]) > 0);
            /* fill metainformation on the client */
            client_metainfo.numattempts = (unsigned int)strtol(argv[1], (char **)NULL, 10);
            client_metainfo.retryinterval = (unsigned int)strtol(argv[0], (char **)NULL, 10);
            client_metainfo.fieldsfilled |= (METAINFO_NUMATTEMPTS | METAINFO_RETRIALINTRV);
            logmsg(LOG_DEBUG, "Query-DeliveryAttempted: found %d attempts over %d secs", client_metainfo.numattempts, sqlr->types.intval);
            break;
        default:
            logmsg(LOG_ERR, "sqcallback: unexpected query type. Forcibly terminating the query.");
            return -1;
    }
    return 0;
}

static int busydb_callback(void *userarg, int numattempts) {
    unsigned int expwait;

/* do not insist more than this many times */
#define MAX_BUSYDB_REATTEMPTS   30

    assert(numattempts >= 0);

    if (numattempts > MAX_BUSYDB_REATTEMPTS)  /* more than this attempts => give up */
        return 0;

    /* wait some milliseconds and try again */
    logmsg(LOG_DEBUG, "Ouch! Database locked (%dth time).", numattempts);
    for (expwait = 10; numattempts > 0; numattempts--) expwait *= 2;
    expwait = (expwait + (random() % 20));
    logmsg(LOG_DEBUG, "Trying again in %u millisecs.", expwait);
    usleep(expwait*1000);
    return 1;
}

void closeall(void) {
    int ret, status;

    /* possibly let the upstream server terminate */
    if (fcntl(rdp[0], F_GETFL, 0) != -1 && fcntl(rdp[1], F_GETFL, 0)) {
        close(rdp[1]);
    }
    /* possibly close db */
    if (db != NULL)
        sqlite3_close(db);

    usleep(30000);
    /* possibly collect child exit status */
    ret = waitpid(-1, & status, WNOHANG);
    if (ret != -1) {
        logmsg(LOG_DEBUG, "Child exited (%d) status %d.", WIFEXITED(status), WEXITSTATUS(status));
    }
}

void sighand(int sig) {
    switch (sig) {
        case SIGALRM:
            logmsg(LOG_WARNING, "Big timeout reached from '%s'!", client_metainfo.address);
            break;
        case SIGPIPE:
            logmsg(LOG_INFO, "Client '%s' closed connection prematurely.", client_metainfo.address);
            break;
    }
    exit(100);
}

void prunedb_pending(void) {
    int ret;
    char *str;

    logmsg(LOG_NOTICE, "Cleaning up stale pending entries.");
    sprintf(buf, "DELETE FROM pending WHERE tsfirstdelivery < DATETIME('now','-%u hours')", STALE_PENDING_ENTRIES_PERIOD);
    logmsg(LOG_DEBUG, "Query: '%s'", buf);
    ret = sqlite3_exec(db, buf, NULL, NULL, &str);
    if (ret != SQLITE_OK) {
        logmsg(LOG_ERR, "Query failed: '%s' -- '%s'", buf, str);
        exit(100);
    }
}

void prunedb_verified(void) {
    int ret;
    char *str;

    logmsg(LOG_NOTICE, "Cleaning up stale verified entries.");
    sprintf(buf, "DELETE FROM verified WHERE ts < DATETIME('now','-%u hours')", STALE_VERIFIED_ENTRIES_PERIOD);
    logmsg(LOG_DEBUG, "Query: '%s'", buf);
    ret = sqlite3_exec(db, buf, NULL, NULL, &str);
    if (ret != SQLITE_OK) {
        logmsg(LOG_ERR, "Query failed: '%s' -- '%s'", buf, str);
        exit(100);
    }
}

