#ifndef LOGMSG_H
#define LOGMSG_H

#include <stdarg.h>


/* log priorities */
#define LOG_EMERG       0       /* system is unusable */
#define LOG_ALERT       1       /* action must be taken immediately */
#define LOG_CRIT        2       /* critical conditions */
#define LOG_ERR         3       /* error conditions */
#define LOG_WARNING     4       /* warning conditions */
#define LOG_NOTICE      5       /* normal but significant condition */
#define LOG_INFO        6       /* informational */
#define LOG_DEBUG       7       /* debug-level messages */


int loglevel;               /* threshold for log messages relevance */
char *logprefix;

int logmsg_init(const char *prefix);
int logmsg(int prio, char *fmt, ...);

#endif