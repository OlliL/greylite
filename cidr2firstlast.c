/**
 * Translates address blocks from CIDR format to first-last address format.
 *
 * Usage:
 * ./cidr2firstlast  and feed address block (like "192.168.0.0/23") in standard input
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main() {
    uint32_t addrfrom, addrto, bitmask;
    char cidr[20];
    char *mask;
    unsigned short int intmask, i;

    while (fgets(cidr, 20, stdin) != NULL) {
        for (i = 0; cidr[i] != '/'; i++);
        cidr[i] = '\0';
        mask = & cidr[i+1];
        intmask = (unsigned short int)strtol(mask, (char **)NULL, 0);

        addrfrom = inet_addr(cidr);
        bitmask = htonl((0x00000001 << (32-intmask))-1);
        addrto = htonl(bitmask | addrfrom);

        printf("%s/%u   -   %s to ", cidr, intmask, cidr);
        printf("%d.%d.%d.%d\n", addrto >> 24, (addrto & 0x00FF0000) >> 16, (addrto & 0x0000FF00) >> 8, addrto & 0x000000FF);
    }

    return 0;
}


