/*
******************************************************************
udpbroadcastrelay (c)2020 Martin Wasley <github.com/marjohn56> & Berto Furth <github.com/bertofurth>
udp-broadcast-relay-redux
    Relays UDP broadcasts to other networks, forging
    the sender address.
Copyright (c) 2017 Michael Morrison <github.com/sonicsnes>
Copyright (c) 2003 Joachim Breitner <mail@joachim-breitner.de>
Copyright (C) 2002 Nathan O'Sullivan
This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
******************************************************************
*/

#define MAXIFS    256
#define MAXMULTICAST 256
#define MAXBLOCKIDS 256
#define MAX_MSEARCH_FILTERS 64
#define MAX_MSEARCH_PROXY 256
#define MAX_LOCATOR_LISTENER 256
#define MAX_LOCATOR_PROXIES 256
#define MAX_REST_LISTENER 256
#define MAX_REST_PROXIES 256

#define MAX_PROXY_SOCKETS (MAX_MSEARCH_PROXY + MAX_LOCATOR_LISTENER + MAX_LOCATOR_PROXIES + MAX_REST_LISTENER + MAX_REST_PROXIES)

/*
 * MAXID used to be 99 when TTL was marked with the ID but
 * now that DSCP is used it needs to be limited to 6 bits.
 */
#define MAXID   63
#define DPRINT  if (debug) printf
#define DPRINT2  if (debug>=2) printf
#define DPRINTTIME  if (debug>=2) printtime()
#define IPHEADER_LEN 20
#define UDPHEADER_LEN 8
#define HEADER_LEN (IPHEADER_LEN + UDPHEADER_LEN)
#define TTL_ID_OFFSET 64
#define SIGF_TERM 0x1

#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdio.h>
#ifdef __FreeBSD__
#include <net/if.h>
#include <net/if_dl.h>
#else
#include <linux/if.h>
#endif
#include <sys/ioctl.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <poll.h>
#include <strings.h>
#include <netdb.h>
#include <fcntl.h>

static int debug = 0;
static char g_pidfile[128];

/* list of addresses and interface numbers on local machine */
struct Iface {
    struct in_addr dstaddr;
    struct in_addr ifaddr;
    char* ifname;
    int ifindex;
    int raw_socket;
};
static struct Iface ifs[MAXIFS];
static int maxifs = 0;

/* Where we forge our packets */
static u_char gram[4096+HEADER_LEN]=
{
    0x45,    0x00,    0x00,    0x26,
    0x12,    0x34,    0x00,    0x00,
    0xFF,    0x11,    0,    0,
    0,    0,    0,    0,
    0,    0,    0,    0,
    0,    0,    0,    0,
    0x00,    0x12,    0x00,    0x00,
    '1','2','3','4','5','6','7','8','9','0'
};
static u_short fragmentID = 0;

/* types of sockets we receive data on */
#define MAIN_SOCKET 0
#define MSEARCH_SOCKET 1
#define LOCSVC_LISTENER 2
#define LOCSVC_CIENTSOCK 3
#define LOCSVC_SERVERSOCK 4
#define RESTSVC_LISTENER 5
#define RESTSVC_CIENTSOCK 6
#define RESTSVC_SERVERSOCK 7

#define MSEARCH_PROXY_EXPIRY 60
#define LOCATOR_LISTENER_EXPIRY 86400
#define REST_LISTENER_EXPIRY 86400

#define BLOCK_RETRY_TIME 10

#define MSEARCH_MARKER "M-SEARCH * HTTP/1.1\r\n"
#define NOTIFY_MARKER "NOTIFY * HTTP/1.1\r\n"
#define LOCATION_STRING_PREFIX "LOCATION: http://"
#define APPLICATION_STRING_PREFIX "Application-URL: http://"

#define MSEARCH_ACTION_FORWARD 1        // Forward M-SEARCH just like other UDP packets
#define MSEARCH_ACTION_BLOCK 2          // Drop M-SEARCH requests with this search string
#define MSEARCH_ACTION_PROXY 3          // Proxy M-SEARCH request an response via udpbroadcastrelay without modifying packet data
#define MSEARCH_ACTION_DIAL 10          // Full DIAL protocol processing proxy

/* Define an individual M-SEARCH filter */
struct MSEARCHFilter {
    char* searchstring;
    int action;
};
static struct MSEARCHFilter msearch_filters[MAX_MSEARCH_FILTERS];
static int num_msearch_filters= 0;
static int default_msearch_action= MSEARCH_ACTION_FORWARD;

/* list of SSDP M-SEARCH reply listener proxies */
struct MSEARCHProxy {
    time_t expirytime;
    unsigned int proxyid;
    struct in_addr clienthost;
    u_short clientport;
    struct Iface* clientiface;
    u_short localport;
    int action;
    int sock;
};
static struct MSEARCHProxy msearch_proxies[MAX_MSEARCH_PROXY];
static int num_msearch_proxies= 0;
static unsigned int next_msearch_proxyid= 0;

/* list of DIAL Locator service listners */
struct LocatorSvcListener {
    time_t expirytime;
    unsigned int listenerid;
    struct in_addr serveraddr;
    u_short serverport;
    struct in_addr localaddr;
    u_short localport;
    int sock;
};
static struct LocatorSvcListener locatorsvc_listeners[MAX_LOCATOR_LISTENER];
static int num_locatorsvc_listeners= 0;
static unsigned int next_locatorsvc_listenerid= 0;

/* list of DIAL Locator service proxies */
struct LocatorSvcProxy {
    unsigned int proxyid;
    int clientsock;
    int serversock;
    struct in_addr serveraddr;
    u_short serverport;
    struct in_addr clientaddr;
    u_short clientport;
    struct in_addr slocaladdr;
    u_short slocalport;
    struct in_addr clocaladdr;
    u_short clocalport;
};
static struct LocatorSvcProxy locatorsvc_proxies[MAX_LOCATOR_PROXIES];
static int num_locatorsvc_proxies= 0;
static unsigned int next_locatorsvc_proxyid= 0;

/* list of REST service listners */
struct RESTSvcListener {
    time_t expirytime;
    unsigned int listenerid;
    struct in_addr serveraddr;
    u_short serverport;
    struct in_addr localaddr;
    u_short localport;
    int sock;
};
static struct RESTSvcListener restsvc_listeners[MAX_REST_LISTENER];
static int num_restsvc_listeners= 0;
static unsigned int next_restsvc_listenerid= 0;

/* list of REST service proxies */
struct RESTSvcProxy {
    unsigned int proxyid;
    int clientsock;
    int serversock;
    struct in_addr serveraddr;
    u_short serverport;
    struct in_addr clientaddr;
    u_short clientport;
    struct in_addr slocaladdr;
    u_short slocalport;
    struct in_addr clocaladdr;
    u_short clocalport;
};
static struct RESTSvcProxy restsvc_proxies[MAX_REST_PROXIES];
static int num_restsvc_proxies= 0;
static unsigned int next_restsvc_proxyid= 0;


char* get_msearch_action_name (int action)
{
    switch (action) {
        case MSEARCH_ACTION_FORWARD:
            return "FORWARD";
        case MSEARCH_ACTION_BLOCK:
            return "BLOCK";
        case MSEARCH_ACTION_PROXY:
            return "PROXY";
        case MSEARCH_ACTION_DIAL:
            return "DIAL";
    }
    return "<unknown>";
}

char ifname_buf[64];
char* ifname_from_idx (int ifindex)
{
    for (int i=0; i<maxifs; i++)
        if (ifs[i].ifindex == ifindex)
            return ifs[i].ifname;
    // shouldn't happen...
    snprintf(ifname_buf, sizeof(ifname_buf), "Idx_%i", ifindex);
    return ifname_buf;
}

void inet_ntoa2(struct in_addr in, char* chr, int len) {
    char* from = inet_ntoa(in);
    strncpy(chr, from, len);
}

// Print formatted current time for log
void printtime (void)
{
    struct timeval tv;
    time_t now;
    long millisec;
    struct tm* tm;
    
    if (gettimeofday(&tv,NULL) == -1)
        return;
    now = tv.tv_sec;
    tm = localtime(&now);
    millisec = tv.tv_usec / 1000;
    printf("%04i/%02i/%02i %02i:%02i:%02i.%03i ", tm->tm_year + 1900, tm->tm_mon + 1,
           tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec, (int) millisec);
}

// Set socket options to receive TTL, TOS, receiving IP and interface for a socket.
// Return 0 on errror.
int enable_recvmsg_headers (int s, char *callername)
{
    int yes = 1;
    #ifdef __FreeBSD__
        if(setsockopt(s, IPPROTO_IP, IP_RECVTTL, &yes, sizeof(yes))<0) {
            fprintf(stderr,"IP_RECVTTL (%s): %s\n",callername,strerror(errno));
            return 0;
        };
        if(setsockopt(s, IPPROTO_IP, IP_RECVTOS, &yes, sizeof(yes))<0) {
            fprintf(stderr,"IP_RECVTOS (%s): %s\n",callername,strerror(errno));
            return 0;
        };
        if(setsockopt(s, IPPROTO_IP, IP_RECVIF, &yes, sizeof(yes))<0) {
            fprintf(stderr,"IP_RECVIF (%s): %s\n",callername,strerror(errno));
            return 0;
        };
        if(setsockopt(s, IPPROTO_IP, IP_RECVDSTADDR, &yes, sizeof(yes))<0) {
            fprintf(stderr,"IP_RECVDSTADDR (%s): %s\n",callername,strerror(errno));
            return 0;
        };
    #else
        if(setsockopt(s, SOL_IP, IP_RECVTTL, &yes, sizeof(yes))<0) {
            fprintf(stderr,"IP_RECVTTL (%s): %s\n",callername,strerror(errno));
            return 0;
        };
        if(setsockopt(s, SOL_IP, IP_RECVTOS, &yes, sizeof(yes))<0) {
            fprintf(stderr,"IP_RECVTOS (%s): %s\n",callername,strerror(errno));
            return 0;
        };
        if(setsockopt(s, SOL_IP, IP_PKTINFO, &yes, sizeof(yes))<0) {
            fprintf(stderr,"IP_PKTINFO (%s): %s\n",callername,strerror(errno));
            return 0;
        };
    #endif
    return 1;
}

// Receive message on socket and return address info. Also check that
// packet was received on a managed interface. to_port is passed in
// for debug print info. Returns number of bytes received or <0 for error
int recv_with_addrinfo (int s, void *buf, size_t buflen, struct Iface **iface_out,
                        struct in_addr *from_inaddr_out, u_short *from_port_out,
                        struct in_addr *to_inaddr_out, u_short to_port)
{
    struct in_addr from_inaddr;
    struct in_addr to_inaddr;
    u_short from_port;
    struct sockaddr_in rcv_addr;
    struct msghdr rcv_msg;
    struct iovec iov;
    iov.iov_base = buf;
    iov.iov_len = buflen;
    u_char pkt_infos[16384];
    int len;

    rcv_msg.msg_name = &rcv_addr;
    rcv_msg.msg_namelen = sizeof(rcv_addr);
    rcv_msg.msg_iov = &iov;
    rcv_msg.msg_iovlen = 1;
    rcv_msg.msg_control = pkt_infos;
    rcv_msg.msg_controllen = sizeof(pkt_infos);

    len = recvmsg(s,&rcv_msg,0);
    if (len <= 0) return len;    /* ignore broken packets */

    from_inaddr = rcv_addr.sin_addr;
    from_port = ntohs(rcv_addr.sin_port);

    /* Find the receiving interface and IP address */
    struct cmsghdr *cmsg;
    int rcv_ifindex = 0;
    int foundRcvIf = 0;
    int foundRcvIp = 0;
    if (rcv_msg.msg_controllen > 0) {
        for (cmsg=CMSG_FIRSTHDR(&rcv_msg);cmsg;cmsg=CMSG_NXTHDR(&rcv_msg,cmsg)) {
            #ifdef __FreeBSD__
                if (cmsg->cmsg_type==IP_RECVDSTADDR) {
                    to_inaddr=*((struct in_addr *)CMSG_DATA(cmsg));
                    foundRcvIp = 1;
                }
                if (cmsg->cmsg_type==IP_RECVIF) {
                    rcv_ifindex=((struct sockaddr_dl *)CMSG_DATA(cmsg))->sdl_index;
                    foundRcvIf = 1;
                }
            #else
                if (cmsg->cmsg_type==IP_PKTINFO) {
                    rcv_ifindex=((struct in_pktinfo *)CMSG_DATA(cmsg))->ipi_ifindex;
                    foundRcvIf = 1;
                    to_inaddr=((struct in_pktinfo *)CMSG_DATA(cmsg))->ipi_addr;
                    foundRcvIp = 1;
                }
            #endif
        }
    }

    if (!foundRcvIp) {
        perror("Source IP not found on incoming packet\n");
        return -2;
    }
    if (!foundRcvIf) {
        perror("Interface not found on incoming packet\n");
        return -2;
    }

    char from_addrstr[255];
    inet_ntoa2(from_inaddr, from_addrstr, sizeof(from_addrstr));
    char to_addrstr[255];
    inet_ntoa2(to_inaddr, to_addrstr, sizeof(to_addrstr));
    DPRINTTIME;
    DPRINT("<- [ %s:%d -> %s:%d (iface=%s len=%i)\n",
        from_addrstr, from_port, to_addrstr, to_port,
        ifname_from_idx(rcv_ifindex), len
    );

    foundRcvIf = 0;
    for (int iIf = 0; iIf < maxifs; iIf++) {
        if (ifs[iIf].ifindex == rcv_ifindex) {
            if (iface_out) *iface_out = &ifs[iIf];
            foundRcvIf = 1;
        }
    }

    if (!foundRcvIf) {
        DPRINT("Not from managed iface\n\n");
        return -3;
    }

    if (from_inaddr_out) *from_inaddr_out = from_inaddr;
    if (from_port_out) *from_port_out = from_port;
    if (to_inaddr_out) *to_inaddr_out = to_inaddr;

    return len;
}

// Bind socket to 0.0.0.0:0 and return the local port number associated with
// the socket or return 0 on error.
u_short get_sock_local_port(int s, in_addr_t localip, char *callername)
{
    struct sockaddr_in bind_addr;
    struct sockaddr_in local_addr;
    socklen_t local_addr_size = sizeof(local_addr);

    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = 0;
    bind_addr.sin_addr.s_addr = localip;

    if(bind(s, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
        fprintf(stderr,"bind (%s): %s\n",callername,strerror(errno));
        return 0;
    }

    if(getsockname(s, (struct sockaddr *)&local_addr, &local_addr_size)<0) {
        fprintf(stderr,"getsockname (%s): %s\n",callername,strerror(errno));
        return 0;
    }
    return ntohs(local_addr.sin_port);
}

int extract_address (char *str, char *prefix, char **addr_start_ptr, char **addr_end_ptr,
                     struct in_addr *ipaddr, u_short *port)
{
    char *startptr = str;
    char *termptr = NULL;
    int prefixlen = strlen(prefix);
    char addrstr[64];
    int addrlen;

    while (*startptr) {
        if (!strncasecmp(startptr,prefix,prefixlen)) {
            break;
        }
        startptr++;
    }

    if (!*startptr) {
        return 0;
    }

    startptr += prefixlen;
    termptr = strchr(startptr,'/');
    if (!termptr) {
        return 0;
    }
    addrlen = termptr-startptr;
    if (addrlen>=sizeof(addrstr)) {
        return 0;
    }

    *addr_start_ptr = startptr;
    *addr_end_ptr = termptr;

    memcpy(addrstr,startptr,addrlen);
    addrstr[addrlen] = 0;
    termptr = strchr(addrstr,':');
    *port = 80;    // default if no port was found
    if (termptr) {
        *termptr = 0;
        *port = atoi(termptr+1);
    }
    struct addrinfo hints;
    struct addrinfo *results;
    memset(&hints,0,sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(addrstr, NULL, &hints, &results) != 0) {
        perror("getaddrinfo");
        return 0;
    }
    *ipaddr = ((struct sockaddr_in*)(results->ai_addr))->sin_addr;
    freeaddrinfo(results);
    return 1;
}

u_short find_or_create_restsvc_listener(struct in_addr servertoaddr, u_short servertoport, struct in_addr listenaddr)
{
    char serveraddrStr[255];
    char localaddrStr[255];

    time_t now = time(NULL);
    int i= 0;
    // Look for an existing proxy for this destination host ip:port
    while (i < num_restsvc_listeners) {
        if (restsvc_listeners[i].expirytime < now) {
            inet_ntoa2(restsvc_listeners[i].serveraddr, serveraddrStr, sizeof(serveraddrStr));
            inet_ntoa2(restsvc_listeners[i].localaddr, localaddrStr, sizeof(localaddrStr));
            DPRINT2("   _Expire REST_Svc listener [id=%u] for proxy to %s:%d on local address %s:%d. %d proxies left\n",
                   restsvc_listeners[i].listenerid,
                   serveraddrStr, restsvc_listeners[i].serverport,
                   localaddrStr, restsvc_listeners[i].localport,
                   num_restsvc_listeners-1
            );
            close(restsvc_listeners[i].sock);
            memcpy(restsvc_listeners+i, restsvc_listeners+(--num_restsvc_listeners), sizeof(*restsvc_listeners));
            continue;
        }
        if( (restsvc_listeners[i].serveraddr.s_addr == servertoaddr.s_addr) &&
            (restsvc_listeners[i].serverport == servertoport) &&
            (restsvc_listeners[i].localaddr.s_addr == listenaddr.s_addr)) {
            inet_ntoa2(restsvc_listeners[i].serveraddr, serveraddrStr, sizeof(serveraddrStr));
            inet_ntoa2(restsvc_listeners[i].localaddr, localaddrStr, sizeof(localaddrStr));
            DPRINT("   Found existing REST_Svc listener [id=%u] for proxy to %s:%d on local address %s:%d.\n",
                   restsvc_listeners[i].listenerid,
                   serveraddrStr, restsvc_listeners[i].serverport,
                   localaddrStr, restsvc_listeners[i].localport
            );
            restsvc_listeners[i].expirytime = now+REST_LISTENER_EXPIRY;    //  Update expiry time
            return restsvc_listeners[i].localport;
        }
        i++;
    }

    // Add new proxy because there is no existing match
    if(num_restsvc_listeners == MAX_REST_LISTENER) {
        DPRINT("Can't add new REST_Svc listener - maximum number of listeners reached\n\n");
        return 0;
    }

    int newsock;
    u_short localport;

    if((newsock=socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
        perror("socket (REST_Svc listener)");
        return 0;
    };

    if ((localport = get_sock_local_port(newsock, listenaddr.s_addr,"LocatorSvc listener")) == 0) {
        close(newsock);
        return 0;
    }

    if(listen(newsock, 3) < 0) {
        perror("listen (REST_Svc listener)");
        close(newsock);
        return 0;
    }

    restsvc_listeners[num_restsvc_listeners].expirytime = now+REST_LISTENER_EXPIRY;
    restsvc_listeners[num_restsvc_listeners].listenerid = next_restsvc_listenerid++;
    restsvc_listeners[num_restsvc_listeners].serveraddr = servertoaddr;
    restsvc_listeners[num_restsvc_listeners].serverport = servertoport;
    restsvc_listeners[num_restsvc_listeners].sock = newsock;
    restsvc_listeners[num_restsvc_listeners].localaddr = listenaddr;
    restsvc_listeners[num_restsvc_listeners].localport = localport;
    num_restsvc_listeners++;

    inet_ntoa2(servertoaddr, serveraddrStr, sizeof(serveraddrStr));
    inet_ntoa2(listenaddr, localaddrStr, sizeof(localaddrStr));
    DPRINT("   Created REST_Svc listener [id=%u] for proxy to %s:%d on local address %s:%d. Total proxies: %d\n",
           restsvc_listeners[num_restsvc_listeners-1].listenerid,
           serveraddrStr, servertoport,
           localaddrStr, localport, num_restsvc_listeners
    );

    return localport;
}

void handle_rest_services_accept (int listerneridx)
{
    int serversock;
    int clientsock;
    struct sockaddr_in clientaddr;
    struct sockaddr_in serveraddr;
    socklen_t clientaddrlen = sizeof(clientaddr);

    char clientaddrStr[255];
    char serveraddrStr[255];

    if ((clientsock = accept(restsvc_listeners[listerneridx].sock, (struct sockaddr *)&clientaddr,
                             &clientaddrlen)) < 0)
    {
        perror("accept (REST_Svc proxy)");
        return;
    }

    int flags;
    if ((flags = fcntl(clientsock, F_GETFL, 0)) < 0) {
        flags = 0;
    }
    if (fcntl(clientsock, F_SETFL, flags | O_NONBLOCK) < 0)
    {
        perror("accept (REST_Svc proxy)");
    }

    inet_ntoa2(clientaddr.sin_addr, clientaddrStr, sizeof(clientaddrStr));
    DPRINT("REST_Svc proxy - accepted connection from client %s:%d\n",
        clientaddrStr, clientaddr.sin_port
    );

    if (num_restsvc_proxies==MAX_REST_PROXIES) {
        DPRINT("... closing connection. No free proxy slots\n");
        close(clientsock);
        return;
    }

    if ((serversock = socket(AF_INET, SOCK_STREAM|SOCK_NONBLOCK, IPPROTO_TCP)) < 0) {
        perror("socket (REST_Svc proxy)");
        close(clientsock);
        return;
    }

    memset(&serveraddr, 0, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons(restsvc_listeners[listerneridx].serverport);
    serveraddr.sin_addr = restsvc_listeners[listerneridx].serveraddr;
    if (connect(serversock, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0) {
        if (errno==EINPROGRESS) {
            // Give the connection 500ms time to complete
            struct pollfd fds[1];
            fds[0].fd = serversock;
            fds[0].events = POLLOUT;
            if (poll(fds,1,500)<1) {
                perror("poll (REST_Svc proxy)");
                close(serversock);
                close(clientsock);
                DPRINT("... closing connection. Connection timeout to peer\n");
                return;
            }
            if (!(fds[0].revents & POLLOUT)) {
                close(serversock);
                close(clientsock);
                DPRINT("... closing connection. Connection to peer not ready for writing\n");
                return;
            }

        } else {
            perror("connect (REST_Svc proxy)");
            close(serversock);
            close(clientsock);
            DPRINT("... closing connection. Connection error to peer\n");
            return;
        }
    }

    // Get local addresses
    struct sockaddr_in lserveraddr;
    struct sockaddr_in lclientaddr;
    socklen_t addrsize = sizeof(lserveraddr);

    memset (&lserveraddr, 0, sizeof(lserveraddr));
    if (getsockname(serversock, (struct sockaddr *)&lserveraddr, &addrsize) < 0) {
        perror("getsockname (REST_Svc proxy lserveraddr)");
    }

    memset (&lclientaddr, 0, sizeof(lclientaddr));
    if (getsockname(clientsock, (struct sockaddr *)&lclientaddr, &addrsize) < 0) {
        perror("getsockname (REST_Svc proxy lclientaddr)");
    }

    // scavange old, closed proxy list entries
    int i= 0;
    while (i < num_restsvc_proxies) {
        if (restsvc_proxies[i].clientsock < 0) {
            inet_ntoa2(restsvc_proxies[i].clientaddr, clientaddrStr, sizeof(clientaddrStr));
            inet_ntoa2(restsvc_proxies[i].serveraddr, serveraddrStr, sizeof(serveraddrStr));
            DPRINT2("   _Scavange REST_Svc proxy [id=%u] for client %s:%d to server %s:%d. %d proxies left\n",
                   restsvc_proxies[i].proxyid,
                   clientaddrStr, restsvc_proxies[i].clientport,
                   serveraddrStr, restsvc_proxies[i].serverport,
                   num_restsvc_proxies-1
            );
            memcpy(restsvc_proxies+i, restsvc_proxies+(--num_restsvc_proxies), sizeof(*restsvc_proxies));
            continue;
        }
        i++;
    }

    // add to proxy list
    restsvc_proxies[num_restsvc_proxies].proxyid = next_restsvc_proxyid++;
    restsvc_proxies[num_restsvc_proxies].clientsock = clientsock;
    restsvc_proxies[num_restsvc_proxies].serversock = serversock;
    restsvc_proxies[num_restsvc_proxies].serveraddr = restsvc_listeners[listerneridx].serveraddr;
    restsvc_proxies[num_restsvc_proxies].serverport = restsvc_listeners[listerneridx].serverport;
    restsvc_proxies[num_restsvc_proxies].clientaddr = clientaddr.sin_addr;
    restsvc_proxies[num_restsvc_proxies].clientport = ntohs(clientaddr.sin_port);
    restsvc_proxies[num_restsvc_proxies].slocaladdr = lserveraddr.sin_addr;
    restsvc_proxies[num_restsvc_proxies].slocalport = ntohs(lserveraddr.sin_port);
    restsvc_proxies[num_restsvc_proxies].clocaladdr = lclientaddr.sin_addr;
    restsvc_proxies[num_restsvc_proxies].clocalport = ntohs(lclientaddr.sin_port);
    num_restsvc_proxies++;

    inet_ntoa2(clientaddr.sin_addr, clientaddrStr, sizeof(clientaddrStr));
    inet_ntoa2(restsvc_listeners[listerneridx].serveraddr, serveraddrStr, sizeof(serveraddrStr));
    DPRINT("   Added LocatorSvc proxy [id=%u] for client %s:%d to server %s:%d. Total proxies: %d\n",
           restsvc_proxies[num_restsvc_proxies-1].proxyid,
           clientaddrStr, restsvc_proxies[num_restsvc_proxies-1].clientport,
           serveraddrStr, restsvc_proxies[num_restsvc_proxies-1].serverport,
           num_restsvc_proxies
    );
}

void handle_restsvc_proxy_recv (int proxyidx, int socktype)
{
    int fromsock, tosock;
    struct in_addr fromaddr;
    struct in_addr fromlocaladdr;
    struct in_addr toaddr;
    struct in_addr tolocaladdr;
    u_short fromport;
    u_short fromlocalport;
    u_short toport;
    u_short tolocalport;

    char toaddrStr[255];
    char fromaddrStr[255];
    char localaddrStr[255];

    if (socktype==RESTSVC_CIENTSOCK) {
        fromsock = restsvc_proxies[proxyidx].clientsock;
        tosock = restsvc_proxies[proxyidx].serversock;
        fromaddr = restsvc_proxies[proxyidx].clientaddr;
        tolocaladdr = restsvc_proxies[proxyidx].clocaladdr;
        toaddr = restsvc_proxies[proxyidx].serveraddr;
        fromlocaladdr = restsvc_proxies[proxyidx].slocaladdr;
        fromport = restsvc_proxies[proxyidx].clientport;
        tolocalport = restsvc_proxies[proxyidx].clocalport;
        toport = restsvc_proxies[proxyidx].serverport;
        fromlocalport = restsvc_proxies[proxyidx].slocalport;
    } else {
        fromsock = restsvc_proxies[proxyidx].serversock;
        tosock = restsvc_proxies[proxyidx].clientsock;
        fromaddr = restsvc_proxies[proxyidx].serveraddr;
        tolocaladdr = restsvc_proxies[proxyidx].slocaladdr;
        toaddr = restsvc_proxies[proxyidx].clientaddr;
        fromlocaladdr = restsvc_proxies[proxyidx].clocaladdr;
        fromport = restsvc_proxies[proxyidx].serverport;
        tolocalport = restsvc_proxies[proxyidx].slocalport;
        toport = restsvc_proxies[proxyidx].clientport;
        fromlocalport = restsvc_proxies[proxyidx].clocalport;
    }

    char buffer[32768];
    int numread;
    int numwritten;
    numread = recv (fromsock, buffer, sizeof(buffer), 0);

    inet_ntoa2(fromaddr, fromaddrStr, sizeof(fromaddrStr));
    inet_ntoa2(tolocaladdr, localaddrStr, sizeof(localaddrStr));
    DPRINTTIME;
    DPRINT("<- TCP [ %s:%d -> %s:%d (len=%i)] to REST_Svc proxy [id=%u]\n",
        fromaddrStr, fromport, localaddrStr, tolocalport,
        numread, restsvc_proxies[proxyidx].proxyid
    );

    if (numread<=0) {
        DPRINT2((numread==0)?
               "   %s connection gracefully closed. Shutting down REST_Svc proxy [id=%u].\n":
               "   Error reading %s socket. Shutting down REST_Svc proxy [id=%u].\n\n",
               socktype==RESTSVC_CIENTSOCK?"Client":"Server", restsvc_proxies[proxyidx].proxyid
        );
        close(restsvc_proxies[proxyidx].clientsock);
        close(restsvc_proxies[proxyidx].serversock);
        restsvc_proxies[proxyidx].clientsock = -1;
        restsvc_proxies[proxyidx].serversock = -1;
        return;
    }

    numwritten = send(tosock, buffer, numread, 0);
    if (numwritten < 0) {
        if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
            inet_ntoa2(toaddr, toaddrStr, sizeof(toaddrStr));
            DPRINT("   REST_Svc proxy [id=%u] would block sending to %s:%d. Retrying in %dms\n",
                   restsvc_proxies[proxyidx].proxyid, toaddrStr, toport, BLOCK_RETRY_TIME);

            struct pollfd fds[1];
            fds[0].fd = tosock;
            fds[0].events = POLLOUT;
            poll(fds,1,BLOCK_RETRY_TIME);

            numwritten = send(tosock, buffer, numread, 0);
            if (numwritten < 0) {
                perror("send (REST_Svc proxy retry)");
                DPRINT("   REST_Svc proxy [id=%u] would block still block. Shutting down proxy\n",
                       restsvc_proxies[proxyidx].proxyid);
                close(restsvc_proxies[proxyidx].clientsock);
                close(restsvc_proxies[proxyidx].serversock);
                restsvc_proxies[proxyidx].clientsock = -1;
                restsvc_proxies[proxyidx].serversock = -1;
                return;
            }
        } else {
            perror("send (REST_Svc proxy)");
            inet_ntoa2(toaddr, toaddrStr, sizeof(toaddrStr));
            DPRINT("   REST_Svc proxy [id=%u] error sending to %s:%d. Shutting down proxy\n",
                   restsvc_proxies[proxyidx].proxyid, toaddrStr, toport);
            close(restsvc_proxies[proxyidx].clientsock);
            close(restsvc_proxies[proxyidx].serversock);
            restsvc_proxies[proxyidx].clientsock = -1;
            restsvc_proxies[proxyidx].serversock = -1;
            return;
        }
    }

    inet_ntoa2(fromlocaladdr, localaddrStr, sizeof(localaddrStr));
    inet_ntoa2(toaddr, toaddrStr, sizeof(toaddrStr));
    inet_ntoa2(fromaddr, fromaddrStr, sizeof(fromaddrStr));
    DPRINTTIME;
    DPRINT("-> TCP [ %s:%d -> %s:%d (len=%i)] for %s %s:%d via REST_Svc proxy [id=%u]\n\n",
        localaddrStr, fromlocalport, toaddrStr, toport, numwritten,
        socktype==RESTSVC_CIENTSOCK?"client":"server",
        fromaddrStr, fromport, restsvc_proxies[proxyidx].proxyid
    );
}

u_short find_or_create_locsvc_listener(struct in_addr servertoaddr, u_short servertoport, struct in_addr listenaddr)
{
    char serveraddrStr[255];
    char localaddrStr[255];

    time_t now = time(NULL);
    int i= 0;
    // Look for an existing proxy for this destination host ip:port
    while (i < num_locatorsvc_listeners) {
        if (locatorsvc_listeners[i].expirytime < now) {
            inet_ntoa2(locatorsvc_listeners[i].serveraddr, serveraddrStr, sizeof(serveraddrStr));
            inet_ntoa2(locatorsvc_listeners[i].localaddr, localaddrStr, sizeof(localaddrStr));
            DPRINT2("   _Expire LocatorSvc listener [id=%u] for proxy to %s:%d on local address %s:%d. %d proxies left\n",
                   locatorsvc_listeners[i].listenerid,
                   serveraddrStr, locatorsvc_listeners[i].serverport,
                   localaddrStr, locatorsvc_listeners[i].localport,
                   num_locatorsvc_listeners-1
            );
            close(locatorsvc_listeners[i].sock);
            memcpy(locatorsvc_listeners+i, locatorsvc_listeners+(--num_locatorsvc_listeners), sizeof(*locatorsvc_listeners));
            continue;
        }
        if( (locatorsvc_listeners[i].serveraddr.s_addr == servertoaddr.s_addr) &&
            (locatorsvc_listeners[i].serverport == servertoport) &&
            (locatorsvc_listeners[i].localaddr.s_addr == listenaddr.s_addr)) {
            inet_ntoa2(locatorsvc_listeners[i].serveraddr, serveraddrStr, sizeof(serveraddrStr));
            inet_ntoa2(locatorsvc_listeners[i].localaddr, localaddrStr, sizeof(localaddrStr));
            DPRINT("   Found existing LocatorSvc listener [id=%u] for proxy to %s:%d on local address %s:%d.\n",
                   locatorsvc_listeners[i].listenerid,
                   serveraddrStr, locatorsvc_listeners[i].serverport,
                   localaddrStr, locatorsvc_listeners[i].localport
            );
            locatorsvc_listeners[i].expirytime = now+LOCATOR_LISTENER_EXPIRY;    //  Update expiry time
            return locatorsvc_listeners[i].localport;
        }
        i++;
    }

    // Add new proxy because there is no existing match
    if(num_locatorsvc_listeners == MAX_LOCATOR_LISTENER) {
        DPRINT("Can't add new LocatorSvc listener - maximum number of listeners reached\n\n");
        return 0;
    }

    int newsock;
    u_short localport;

    if((newsock=socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
        perror("socket (LocatorSvc listener)");
        return 0;
    };

    if ((localport = get_sock_local_port(newsock, listenaddr.s_addr,"LocatorSvc listener")) == 0) {
        close(newsock);
        return 0;
    }

    if(listen(newsock, 3) < 0) {
        perror("listen (LocatorSvc listener)");
        close(newsock);
        return 0;
    }

    locatorsvc_listeners[num_locatorsvc_listeners].expirytime = now+LOCATOR_LISTENER_EXPIRY;
    locatorsvc_listeners[num_locatorsvc_listeners].listenerid = next_locatorsvc_listenerid++;
    locatorsvc_listeners[num_locatorsvc_listeners].serveraddr = servertoaddr;
    locatorsvc_listeners[num_locatorsvc_listeners].serverport = servertoport;
    locatorsvc_listeners[num_locatorsvc_listeners].sock = newsock;
    locatorsvc_listeners[num_locatorsvc_listeners].localaddr = listenaddr;
    locatorsvc_listeners[num_locatorsvc_listeners].localport = localport;
    num_locatorsvc_listeners++;

    inet_ntoa2(servertoaddr, serveraddrStr, sizeof(serveraddrStr));
    inet_ntoa2(listenaddr, localaddrStr, sizeof(localaddrStr));
    DPRINT("   Created LocatorSvc listener [id=%u] for proxy to %s:%d on local address %s:%d. Total proxies: %d\n",
           locatorsvc_listeners[num_locatorsvc_listeners-1].listenerid,
           serveraddrStr, servertoport,
           localaddrStr, localport, num_locatorsvc_listeners
    );

    return localport;
}

void handle_loc_services_accept (int listerneridx)
{
    int serversock;
    int clientsock;
    struct sockaddr_in clientaddr;
    struct sockaddr_in serveraddr;
    socklen_t clientaddrlen = sizeof(clientaddr);

    char clientaddrStr[255];
    char serveraddrStr[255];

    if ((clientsock = accept(locatorsvc_listeners[listerneridx].sock, (struct sockaddr *)&clientaddr,
                             &clientaddrlen)) < 0)
    {
        perror("accept (LocatorSvc proxy)");
        return;
    }

    int flags;
    if ((flags = fcntl(clientsock, F_GETFL, 0)) < 0) {
        flags = 0;
    }
    if (fcntl(clientsock, F_SETFL, flags | O_NONBLOCK) < 0)
    {
        perror("accept (LocatorSvc proxy)");
    }

    inet_ntoa2(clientaddr.sin_addr, clientaddrStr, sizeof(clientaddrStr));
    DPRINT("LocatorSvc proxy - accepted connection from client %s:%d\n",
        clientaddrStr, clientaddr.sin_port
    );

    if (num_locatorsvc_proxies==MAX_LOCATOR_PROXIES) {
        DPRINT("... closing connection. No free proxy slots\n");
        close(clientsock);
        return;
    }

    if ((serversock = socket(AF_INET, SOCK_STREAM|SOCK_NONBLOCK, IPPROTO_TCP)) < 0) {
        perror("socket (LocatorSvc proxy)");
        close(clientsock);
        return;
    }

    memset(&serveraddr, 0, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons(locatorsvc_listeners[listerneridx].serverport);
    serveraddr.sin_addr = locatorsvc_listeners[listerneridx].serveraddr;
    if (connect(serversock, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0) {
        if (errno==EINPROGRESS) {
            // Give the connection 500ms time to complete
            struct pollfd fds[1];
            fds[0].fd = serversock;
            fds[0].events = POLLOUT;
            if (poll(fds,1,500)<1) {
                perror("poll (LocatorSvc proxy)");
                close(serversock);
                close(clientsock);
                DPRINT("... closing connection. Connection timeout to peer\n");
                return;
            }
            if (!(fds[0].revents & POLLOUT)) {
                close(serversock);
                close(clientsock);
                DPRINT("... closing connection. Connection to peer not ready for writing\n");
                return;
            }

        } else {
            perror("connect (LocatorSvc proxy)");
            close(serversock);
            close(clientsock);
            DPRINT("... closing connection. Connection error to peer\n");
            return;
        }
    }

    // Get local addresses
    struct sockaddr_in lserveraddr;
    struct sockaddr_in lclientaddr;
    socklen_t addrsize = sizeof(lserveraddr);

    memset (&lserveraddr, 0, sizeof(lserveraddr));
    if (getsockname(serversock, (struct sockaddr *)&lserveraddr, &addrsize) < 0) {
        perror("getsockname (LocatorSvc proxy lserveraddr)");
    }

    memset (&lclientaddr, 0, sizeof(lclientaddr));
    if (getsockname(clientsock, (struct sockaddr *)&lclientaddr, &addrsize) < 0) {
        perror("getsockname (LocatorSvc proxy lclientaddr)");
    }

    // scavange old, closed proxy list entries
    int i= 0;
    while (i < num_locatorsvc_proxies) {
        if (locatorsvc_proxies[i].clientsock < 0) {
            inet_ntoa2(locatorsvc_proxies[i].clientaddr, clientaddrStr, sizeof(clientaddrStr));
            inet_ntoa2(locatorsvc_proxies[i].serveraddr, serveraddrStr, sizeof(serveraddrStr));
            DPRINT2("   _Scavange LocatorSvc proxy [id=%u] for client %s:%d to server %s:%d. %d proxies left\n",
                   locatorsvc_proxies[i].proxyid,
                   clientaddrStr, locatorsvc_proxies[i].clientport,
                   serveraddrStr, locatorsvc_proxies[i].serverport,
                   num_locatorsvc_proxies-1
            );
            memcpy(locatorsvc_proxies+i, locatorsvc_proxies+(--num_locatorsvc_proxies), sizeof(*locatorsvc_proxies));
            continue;
        }
        i++;
    }

    // add to proxy list
    locatorsvc_proxies[num_locatorsvc_proxies].proxyid = next_locatorsvc_proxyid++;
    locatorsvc_proxies[num_locatorsvc_proxies].clientsock = clientsock;
    locatorsvc_proxies[num_locatorsvc_proxies].serversock = serversock;
    locatorsvc_proxies[num_locatorsvc_proxies].serveraddr = locatorsvc_listeners[listerneridx].serveraddr;
    locatorsvc_proxies[num_locatorsvc_proxies].serverport = locatorsvc_listeners[listerneridx].serverport;
    locatorsvc_proxies[num_locatorsvc_proxies].clientaddr = clientaddr.sin_addr;
    locatorsvc_proxies[num_locatorsvc_proxies].clientport = ntohs(clientaddr.sin_port);
    locatorsvc_proxies[num_locatorsvc_proxies].slocaladdr = lserveraddr.sin_addr;
    locatorsvc_proxies[num_locatorsvc_proxies].slocalport = ntohs(lserveraddr.sin_port);
    locatorsvc_proxies[num_locatorsvc_proxies].clocaladdr = lclientaddr.sin_addr;
    locatorsvc_proxies[num_locatorsvc_proxies].clocalport = ntohs(lclientaddr.sin_port);
    num_locatorsvc_proxies++;

    inet_ntoa2(clientaddr.sin_addr, clientaddrStr, sizeof(clientaddrStr));
    inet_ntoa2(locatorsvc_listeners[listerneridx].serveraddr, serveraddrStr, sizeof(serveraddrStr));
    DPRINT("   Added LocatorSvc proxy [id=%u] for client %s:%d to server %s:%d. Total proxies: %d\n",
           locatorsvc_proxies[num_locatorsvc_proxies-1].proxyid,
           clientaddrStr, locatorsvc_proxies[num_locatorsvc_proxies-1].clientport,
           serveraddrStr, locatorsvc_proxies[num_locatorsvc_proxies-1].serverport,
           num_locatorsvc_proxies
    );
}

void handle_locsvc_proxy_recv (int proxyidx, int socktype)
{
    int fromsock, tosock;
    struct in_addr fromaddr;
    struct in_addr fromlocaladdr;
    struct in_addr toaddr;
    struct in_addr tolocaladdr;
    u_short fromport;
    u_short fromlocalport;
    u_short toport;
    u_short tolocalport;

    char toaddrStr[255];
    char fromaddrStr[255];
    char localaddrStr[255];

    if (socktype==LOCSVC_CIENTSOCK) {
        fromsock = locatorsvc_proxies[proxyidx].clientsock;
        tosock = locatorsvc_proxies[proxyidx].serversock;
        fromaddr = locatorsvc_proxies[proxyidx].clientaddr;
        tolocaladdr = locatorsvc_proxies[proxyidx].clocaladdr;
        toaddr = locatorsvc_proxies[proxyidx].serveraddr;
        fromlocaladdr = locatorsvc_proxies[proxyidx].slocaladdr;
        fromport = locatorsvc_proxies[proxyidx].clientport;
        tolocalport = locatorsvc_proxies[proxyidx].clocalport;
        toport = locatorsvc_proxies[proxyidx].serverport;
        fromlocalport = locatorsvc_proxies[proxyidx].slocalport;
    } else {
        fromsock = locatorsvc_proxies[proxyidx].serversock;
        tosock = locatorsvc_proxies[proxyidx].clientsock;
        fromaddr = locatorsvc_proxies[proxyidx].serveraddr;
        tolocaladdr = locatorsvc_proxies[proxyidx].slocaladdr;
        toaddr = locatorsvc_proxies[proxyidx].clientaddr;
        fromlocaladdr = locatorsvc_proxies[proxyidx].clocaladdr;
        fromport = locatorsvc_proxies[proxyidx].serverport;
        tolocalport = locatorsvc_proxies[proxyidx].slocalport;
        toport = locatorsvc_proxies[proxyidx].clientport;
        fromlocalport = locatorsvc_proxies[proxyidx].clocalport;
    }

    char buffer[32768];
    int numread;
    int numwritten;
    numread = recv (fromsock, buffer, sizeof(buffer)-1, 0);

    inet_ntoa2(fromaddr, fromaddrStr, sizeof(fromaddrStr));
    inet_ntoa2(tolocaladdr, localaddrStr, sizeof(localaddrStr));
    DPRINTTIME;
    DPRINT("<- TCP [ %s:%d -> %s:%d (len=%i)] to LocatorSvc proxy [id=%u]\n",
        fromaddrStr, fromport, localaddrStr, tolocalport,
        numread, locatorsvc_proxies[proxyidx].proxyid
    );

    if (numread<=0) {
        DPRINT2((numread==0)?
               "   %s connection gracefully closed. Shutting down LocatorSvc proxy [id=%u].\n":
               "   Error reading %s socket. Shutting down LocatorSvc proxy [id=%u].\n\n",
               socktype==LOCSVC_CIENTSOCK?"Client":"Server", locatorsvc_proxies[proxyidx].proxyid
        );
        close(locatorsvc_proxies[proxyidx].clientsock);
        close(locatorsvc_proxies[proxyidx].serversock);
        locatorsvc_proxies[proxyidx].clientsock = -1;
        locatorsvc_proxies[proxyidx].serversock = -1;
        return;
    }

    buffer[numread] = 0;

    if (socktype==LOCSVC_SERVERSOCK) {
        // Inspect payload and insert REST_Svc proxy if required
        char *addrStartPtr;
        char *addrEndPtr;
        struct in_addr serverAddr;
        u_short serverPort;

        if (extract_address(buffer, APPLICATION_STRING_PREFIX, &addrStartPtr,
                            &addrEndPtr, &serverAddr, &serverPort)) {
             struct in_addr proxyAddress = locatorsvc_proxies[proxyidx].clocaladdr;
            u_short proxyPort = find_or_create_restsvc_listener(serverAddr, serverPort, proxyAddress);
            if (proxyPort) {
                char addrstr[64];
                char proxyAddrStr[56];
                inet_ntoa2(proxyAddress, proxyAddrStr, sizeof(proxyAddrStr));
                snprintf(addrstr, sizeof(addrstr), "%s:%d", proxyAddrStr, proxyPort);

                int lengthChange = strlen(addrstr) - (addrEndPtr-addrStartPtr);
                if ((numread+lengthChange) < sizeof(buffer)) {
                    memmove(addrEndPtr+lengthChange, addrEndPtr, buffer + numread + 1 - addrEndPtr);
                    memcpy(addrStartPtr, addrstr, strlen(addrstr));
                }
            } else {
                DPRINT("Could not find a free REST services proxy slot - sending unmodified response\n\n");
            }
        }
    }

    numwritten = send(tosock, buffer, numread, 0);
    if (numwritten < 0) {
        if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
            inet_ntoa2(toaddr, toaddrStr, sizeof(toaddrStr));
            DPRINT("   LocatorSvc proxy [id=%u] would block sending to %s:%d. Retrying in %dms\n",
                   locatorsvc_proxies[proxyidx].proxyid, toaddrStr, toport, BLOCK_RETRY_TIME);

            struct pollfd fds[1];
            fds[0].fd = tosock;
            fds[0].events = POLLOUT;
            poll(fds,1,BLOCK_RETRY_TIME);

            numwritten = send(tosock, buffer, numread, 0);
            if (numwritten < 0) {
                perror("send (LocatorSvc proxy retry)");
                DPRINT("   LocatorSvc proxy [id=%u] would block still block. Shutting down proxy\n",
                       locatorsvc_proxies[proxyidx].proxyid);
                close(locatorsvc_proxies[proxyidx].clientsock);
                close(locatorsvc_proxies[proxyidx].serversock);
                locatorsvc_proxies[proxyidx].clientsock = -1;
                locatorsvc_proxies[proxyidx].serversock = -1;
                return;
            }
        } else {
            perror("send (LocatorSvc proxy)");
            inet_ntoa2(toaddr, toaddrStr, sizeof(toaddrStr));
            DPRINT("   LocatorSvc proxy [id=%u] error sending to %s:%d. Shutting down proxy\n",
                   locatorsvc_proxies[proxyidx].proxyid, toaddrStr, toport);
            close(locatorsvc_proxies[proxyidx].clientsock);
            close(locatorsvc_proxies[proxyidx].serversock);
            locatorsvc_proxies[proxyidx].clientsock = -1;
            locatorsvc_proxies[proxyidx].serversock = -1;
            return;
        }
    }

    inet_ntoa2(fromlocaladdr, localaddrStr, sizeof(localaddrStr));
    inet_ntoa2(toaddr, toaddrStr, sizeof(toaddrStr));
    inet_ntoa2(fromaddr, fromaddrStr, sizeof(fromaddrStr));
    DPRINTTIME;
    DPRINT("-> TCP [ %s:%d -> %s:%d (len=%i)] for %s %s:%d via LocatorSvc proxy [id=%u]\n\n",
        localaddrStr, fromlocalport, toaddrStr, toport, numwritten,
        socktype==LOCSVC_CIENTSOCK?"client":"server",
        fromaddrStr, fromport, locatorsvc_proxies[proxyidx].proxyid
    );
}

// Find the M-SEARCH request proxy for a given client and return the UDP port
// number on which the proxy listens. Return 0 if no proxy was found and a new
// one could not be created. Also expire old proxies that have not been used.
u_short find_or_create_msearch_proxy(struct in_addr clientfromaddr, u_short clientfromport, struct Iface* iface, int action) {
    time_t now = time(NULL);
    int i= 0;
    // Look for an existing proxy for this source host ip:port
    while (i < num_msearch_proxies) {
        if (msearch_proxies[i].expirytime < now) {
            char clienthostStr[255];
            inet_ntoa2(msearch_proxies[i].clienthost, clienthostStr, sizeof(clienthostStr));
            DPRINT2("   _Expire M-SEARCH proxy [id=%u] for %s:%d on local port %d. %d proxies left\n",
                   msearch_proxies[i].proxyid, clienthostStr,
                   msearch_proxies[i].clientport, msearch_proxies[i].localport,
                   num_msearch_proxies-1
            );
            close(msearch_proxies[i].sock);
            memcpy(msearch_proxies+i, msearch_proxies+(--num_msearch_proxies), sizeof(*msearch_proxies));
            continue;
        }
        if( (msearch_proxies[i].clienthost.s_addr == clientfromaddr.s_addr) &&
            (msearch_proxies[i].clientport == clientfromport) ) {
            char clienthostStr[255];
            inet_ntoa2(msearch_proxies[i].clienthost, clienthostStr, sizeof(clienthostStr));
            DPRINT("   Found existing M-SEARCH proxy [id=%u] for %s:%d on local port %d.\n",
                   msearch_proxies[i].proxyid, clienthostStr,
                   msearch_proxies[i].clientport, msearch_proxies[i].localport
            );
            msearch_proxies[i].expirytime = now+MSEARCH_PROXY_EXPIRY;    //  Update expiry time
            return msearch_proxies[i].localport;
        }
        i++;
    }

    // Add new proxy because there is no existing match
    if(num_msearch_proxies == MAX_MSEARCH_PROXY) {
        DPRINT("Can't add new M-SEARCH proxy - maximum number of proxies reached\n\n");
        return 0;
    }

    int newsock;
    u_short localport;

    if((newsock=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP)) < 0) {
        perror("socket (M-SEARCH proxy)");
        return 0;
    };

    if(!enable_recvmsg_headers(newsock, "M-SEARCH proxy")) {
        close(newsock);
        return 0;
    }

    localport = get_sock_local_port(newsock, INADDR_ANY, "M-SEARCH proxy");
    if(!localport) {
        close(newsock);
        return 0;
    }

    msearch_proxies[num_msearch_proxies].expirytime = now+MSEARCH_PROXY_EXPIRY;
    msearch_proxies[num_msearch_proxies].proxyid = next_msearch_proxyid++;
    msearch_proxies[num_msearch_proxies].clienthost = clientfromaddr;
    msearch_proxies[num_msearch_proxies].clientport = clientfromport;
    msearch_proxies[num_msearch_proxies].sock = newsock;
    msearch_proxies[num_msearch_proxies].clientiface= iface;
    msearch_proxies[num_msearch_proxies].localport = localport;
    msearch_proxies[num_msearch_proxies].action = action;
    num_msearch_proxies++;

    char clientfromaddrStr[255];
    inet_ntoa2(clientfromaddr, clientfromaddrStr, sizeof(clientfromaddrStr));
    DPRINT("   Created M-SEARCH proxy [id=%u] for %s:%d on local port %d. Total proxies: %d\n",
           msearch_proxies[num_msearch_proxies-1].proxyid, clientfromaddrStr, clientfromport, localport, num_msearch_proxies
    );

    return localport;
}

void handle_msearch_proxy_recv (int proxyidx)
{
    struct Iface* iface = msearch_proxies[proxyidx].clientiface;
    int len = recv_with_addrinfo(msearch_proxies[proxyidx].sock, gram+HEADER_LEN,
                                 sizeof(gram)-HEADER_LEN-1, NULL,
                                 NULL, NULL, NULL, msearch_proxies[proxyidx].localport);
    if (len <= 0) return;    /* ignore broken packets */
    gram[HEADER_LEN + len] = 0;

    char *addrStartPtr;
    char *addrEndPtr;
    struct in_addr serverAddr;
    u_short serverPort;

    if ( (msearch_proxies[proxyidx].action == MSEARCH_ACTION_DIAL) &&
         (extract_address((char*)gram + HEADER_LEN, LOCATION_STRING_PREFIX, &addrStartPtr,
                          &addrEndPtr, &serverAddr, &serverPort)) ) {
        struct in_addr proxyAddress = iface->ifaddr;
        u_short proxyPort = find_or_create_locsvc_listener(serverAddr, serverPort, proxyAddress);
        if (proxyPort) {
            char addrstr[64];
            char proxyAddrStr[56];
            inet_ntoa2(proxyAddress, proxyAddrStr, sizeof(proxyAddrStr));
            snprintf(addrstr, sizeof(addrstr), "%s:%d", proxyAddrStr, proxyPort);
            DPRINT("   Updating M-SEARCH Locator address from %.*s to %s\n",
                   (int)(addrEndPtr-addrStartPtr), addrStartPtr, addrstr);

            int lengthChange = strlen(addrstr) - (addrEndPtr-addrStartPtr);
            if ((len+lengthChange) < (sizeof(gram)-HEADER_LEN)) {
                memmove(addrEndPtr+lengthChange, addrEndPtr, (char*)gram + HEADER_LEN + len + 1 - addrEndPtr);
                memcpy(addrStartPtr, addrstr, strlen(addrstr));
            }
        } else {
            DPRINT("Could not find a free Locator services proxy slot - sending unmodified response\n\n");
        }
    }

    struct in_addr fromAddress = iface->ifaddr;
    u_short fromPort = msearch_proxies[proxyidx].localport;
    struct in_addr toAddress = msearch_proxies[proxyidx].clienthost;
    u_short toPort = msearch_proxies[proxyidx].clientport;

    char fromAddressStr[255];
    inet_ntoa2(fromAddress, fromAddressStr, sizeof(fromAddressStr));
    char toAddressStr[255];
    inet_ntoa2(toAddress, toAddressStr, sizeof(toAddressStr));
    DPRINT2 ("   Returning M-SEARCH response via m-search proxy [id=%u]\n", msearch_proxies[proxyidx].proxyid);
    DPRINTTIME;
    DPRINT ("-> [ %s:%d -> %s:%d (iface=%s len=%i)]\n\n", fromAddressStr, fromPort,
            toAddressStr, toPort, ifname_from_idx(iface->ifindex), len);

    gram[1] = 0;    // rcv_tos
    gram[8] = 16;   // rcv_ttl;
    memcpy(gram+12, &fromAddress.s_addr, 4);
    memcpy(gram+16, &toAddress.s_addr, 4);
    *(u_short*)(gram+4)=htons(fragmentID++);
    *(u_short*)(gram+20)=htons(fromPort);
    *(u_short*)(gram+22)=htons(toPort);
    #if (defined __FreeBSD__ && __FreeBSD__ <= 10) || defined __APPLE__
    *(u_short*)(gram+24)=htons(UDPHEADER_LEN + len);
    *(u_short*)(gram+2)=HEADER_LEN + len;
    #else
    *(u_short*)(gram+24)=htons(UDPHEADER_LEN + len);
    *(u_short*)(gram+2)=htons(HEADER_LEN + len);
    #endif
    struct sockaddr_in sendAddr;
    sendAddr.sin_family = AF_INET;
    sendAddr.sin_port = htons(toPort);
    sendAddr.sin_addr = toAddress;

    if (sendto(
        iface->raw_socket,
        &gram,
        HEADER_LEN+len,
        0,
        (struct sockaddr*)&sendAddr,
        sizeof(sendAddr)
    ) < 0) {
        perror("sendto");
    }
}

// Look at list of M-SEARCH filters to determine how to handle a particular packet. A return value of 0 means
// the packet should be dropped. if non-zero, proxyPort will either be 0 (forward packet as normal) or contain
// the UDP port number of a proxy instance.
int check_msearch_filters (struct in_addr clientfromaddr, u_short clientfromport, struct Iface* iface, u_short* proxyPort)
{
    char* CRLF;
    char* ST;
    int STlen;
    int action = -1;
    
    // Check that we have a M-SEARCH request header
    if (memcmp(gram + HEADER_LEN, MSEARCH_MARKER, strlen(MSEARCH_MARKER))) {
        // M-SEARCH header not found. Also check NOTIFY header for debugging purposes
        if (!memcmp(gram + HEADER_LEN, NOTIFY_MARKER, strlen(NOTIFY_MARKER))) {
            ST = (char*)gram + HEADER_LEN + strlen(NOTIFY_MARKER);
            CRLF = strstr(ST, "\r\n");
            while (CRLF) {
                // Look for "NT:" header (case insensitive)
                if ( ((ST[0]|0x20) == 'n') && ((ST[1]|0x20) == 't') && (ST[2] == ':') ) {
                    // Skip past any possible white-space
                    ST += 3;
                    while ((*ST == ' ') || (*ST == '\t')) {
                        ST++;
                    }
                    STlen = CRLF - ST;
                    DPRINT2("   Found NOTIFY search term %.*s\n", STlen, ST);
                    break;
                }
                ST = CRLF + 2;
                CRLF = strstr(ST, "\r\n");
            }
        }
        // Indicate packet should be forwarded as normal
        *proxyPort = 0;
        return 1;
    }

    ST = (char*)gram + HEADER_LEN + strlen(MSEARCH_MARKER);
    CRLF = strstr(ST, "\r\n");
    while (CRLF) {
        // Look for "ST:" header (case insensitive)
        if ( ((ST[0]|0x20) == 's') && ((ST[1]|0x20) == 't') && (ST[2] == ':') ) {
            // Skip past any possible white-space
            ST += 3;
            while ((*ST == ' ') || (*ST == '\t')) {
                ST++;
            }
            STlen = CRLF - ST;
            DPRINT2("   Found M-SEARCH search term %.*s\n", STlen, ST);

            // Compare ST search term with saved search filters
            for (int i=0; i < num_msearch_filters; i++) {
                if ( strncmp(msearch_filters[i].searchstring, ST, STlen) ||
                     msearch_filters[i].searchstring[STlen] )
                    continue;
                action = msearch_filters[i].action;
                DPRINT2("   Matched ST filter and found action %s\n", get_msearch_action_name(action));
                break;
            }
            break;
        }
        ST = CRLF + 2;
        CRLF = strstr(ST, "\r\n");
    }
    // Apply default msearch action
    if (action < 0) {
        action = default_msearch_action;
        DPRINT2("   Applying default action %s\n", get_msearch_action_name(action));
    }

    if (action == MSEARCH_ACTION_FORWARD) {
        *proxyPort = 0;
        return 1;
    }
    else if ( (action == MSEARCH_ACTION_PROXY) || (action == MSEARCH_ACTION_DIAL) ) {
        *proxyPort = find_or_create_msearch_proxy(clientfromaddr, clientfromport, iface, action);
        if (!*proxyPort) {
            DPRINT("Could not find a free M-SEARCH proxy slot, dropping packet\n\n");
            return 0;
        }
        return 1;
    }
    else if (action == MSEARCH_ACTION_BLOCK) {
        DPRINT("\n");
        return 0;
    }
    DPRINT("   Unknown action %i, dropping packet\n\n", action);
    return 0;   // Treat unknown action as BLOCK
}

void service_proxy_messages (int main_rcv_sock)
{
    while (1) {
        // Poll for any sockets with pending operations (read/close)
        // Important - sockets are serviced in the order they are added to the poll
        // list. REST and Locator service proxies MUST handled before any other sockets
        // to avoid corrupting data structures when removing closed proxy entries
        struct pollfd fds[MAX_PROXY_SOCKETS+1];
        int proxy_array_idx[MAX_PROXY_SOCKETS+1];
        char proxy_socket_type[MAX_PROXY_SOCKETS+1];
        int total_fds= 0;
        int i;

        memset(fds, 0, sizeof(fds));

        for (int i=0;i<num_restsvc_proxies;i++) {
            fds[total_fds].fd = restsvc_proxies[i].clientsock;
            fds[total_fds].events = POLLIN;
            proxy_array_idx[total_fds] = i;
            proxy_socket_type[total_fds] = RESTSVC_CIENTSOCK;
            total_fds++;
            fds[total_fds].fd = restsvc_proxies[i].serversock;
            fds[total_fds].events = POLLIN;
            proxy_array_idx[total_fds] = i;
            proxy_socket_type[total_fds] = RESTSVC_SERVERSOCK;
            total_fds++;
        }

        for (int i=0;i<num_locatorsvc_proxies;i++) {
            fds[total_fds].fd = locatorsvc_proxies[i].clientsock;
            fds[total_fds].events = POLLIN;
            proxy_array_idx[total_fds] = i;
            proxy_socket_type[total_fds] = LOCSVC_CIENTSOCK;
            total_fds++;
            fds[total_fds].fd = locatorsvc_proxies[i].serversock;
            fds[total_fds].events = POLLIN;
            proxy_array_idx[total_fds] = i;
            proxy_socket_type[total_fds] = LOCSVC_SERVERSOCK;
            total_fds++;
        }

        for (int i=0;i<num_restsvc_listeners;i++) {
            fds[total_fds].fd = restsvc_listeners[i].sock;
            fds[total_fds].events = POLLIN;
            proxy_array_idx[total_fds] = i;
            proxy_socket_type[total_fds] = RESTSVC_LISTENER;
            total_fds++;
        }

        for (int i=0;i<num_locatorsvc_listeners;i++) {
            fds[total_fds].fd = locatorsvc_listeners[i].sock;
            fds[total_fds].events = POLLIN;
            proxy_array_idx[total_fds] = i;
            proxy_socket_type[total_fds] = LOCSVC_LISTENER;
            total_fds++;
        }
        for (int i=0;i<num_msearch_proxies;i++) {
            fds[total_fds].fd = msearch_proxies[i].sock;
            fds[total_fds].events = POLLIN;
            proxy_array_idx[total_fds] = i;
            proxy_socket_type[total_fds] = MSEARCH_SOCKET;
            total_fds++;
        }

        // Main socket should be the last element in the list
        fds[total_fds].fd = main_rcv_sock;
        fds[total_fds].events = POLLIN;
        proxy_array_idx[total_fds] = 0;
        proxy_socket_type[total_fds] = MAIN_SOCKET;
        total_fds++;

        // Poll for any sockets with data to read
        if (poll(fds, total_fds, -1) < 0) {
            perror("poll\n");
            continue;
        }

        for (i=0;i<=total_fds;i++) {
            // Skip socket if there is no data ready to read
            if ( !(fds[i].revents & POLLIN) ) continue;

            switch (proxy_socket_type[i]) {
                case MAIN_SOCKET:
                        return;

                case MSEARCH_SOCKET:
                        handle_msearch_proxy_recv(proxy_array_idx[i]);
                        break;

                case LOCSVC_LISTENER:
                        handle_loc_services_accept(proxy_array_idx[i]);
                        break;

                case LOCSVC_CIENTSOCK:
                case LOCSVC_SERVERSOCK:
                        handle_locsvc_proxy_recv(proxy_array_idx[i], proxy_socket_type[i]);
                        break;

                case RESTSVC_LISTENER:
                        handle_rest_services_accept(proxy_array_idx[i]);
                        break;

                case RESTSVC_CIENTSOCK:
                case RESTSVC_SERVERSOCK:
                        handle_restsvc_proxy_recv(proxy_array_idx[i], proxy_socket_type[i]);
                        break;
            }
        }
    }
}

void sig_term_handler(int signum, siginfo_t *info, void *ptr)
{
    unlink(g_pidfile);
    exit(0);
}

void catch_sigterm()
{
    static struct sigaction _sigact;

    memset(&_sigact, 0, sizeof(_sigact));
    _sigact.sa_sigaction = sig_term_handler;
    _sigact.sa_flags = SA_SIGINFO;

    sigaction(SIGTERM, &_sigact, NULL);
}

void display_usage(FILE *stream, const char *arg0) {
    fprintf(stream, "usage: %s [--id ID] [--port udp-port]\n"
            "       [--dev dev1] [--dev dev2] [--dev devX]\n"
            "       [-s IP] [--multicast ip1] [--multicast ipX]\n"
            "       [-t|--ttl-id] [-d] [-f]\n"
            "       [-h|--help]\n", arg0);
}

void display_help(const char *arg0) {
    printf("This program listens for packets on a specified UDP broadcast\n"
           "port. When a packet is received, it sends that packet to all\n"
           "specified interfaces but the one it came from as though it\n"
           "originated from the original sender.\n"
           "The primary purpose of this is to allow devices or game servers\n"
           "on separated local networks (Ethernet, WLAN, VLAN) that use udp\n"
           "broadcasts to find each other to do so.\n");
    printf("Required Parameters:\n"
           "  --id ID  Set a unique ID for this instance of the tool.\n"
           "           Valid range 1 - %i. The IP DSCP field of a relayed\n"
           "           packet is set to this value so the tool may\n"
           "           identify and drop already relayed packets in order\n"
           "           to avoid packet storms.\n"
           "  --port udp-port   Destination UDP port to listen for.\n"
           "                    Valid range 1 - 65535.\n"
           "                    e.g.  5353 - mDNS/Chromecast/Apple Bonjour\n"
           "                          1900 - UPnP Discovery/SSDP\n"
           "                          37 - NetBIOS name service (Windows)\n"
           "                          38 - SMB Browser (Windows)\n"
           "                    Only specify one udp-port per instance.\n"
           "  --dev device   Name of an interface to listen for and to \n"
           "                 relay packets to. This option must be specified\n"
           "                 at least twice for two separate interfaces in\n"
           "                 order for this tool to have any effect.\n", MAXID);
    printf("Optional Parameters:\n"
           "  -s IP    Sets the source IP of forwarded packets. If not\n"
           "           specified the original IP source address is used.\n"
           "           Special values :\n"
           "           1.1.1.1 - Use the outgoing interface ip address as\n"
           "                     source IP. Also forces the outgoing packet\n"
           "                     source UDP port to the same as the destination\n"
           "                     UDP port.\n"
           "           1.1.1.2 - Use the outgoing interface ip address as \n"
           "                     source IP. Does not modify UDP ports.\n"
           "           These special values help in rare cases e.g. Chromecast\n"
           "  --msearch action[,search-term]\n"
           "           Enable special handling of SSDP M-SEARCH requests. The\n"
           "           action parameter can be one of the following values:\n"
           "               block     Block M-SEARCH requests\n"
           "               fwd       Forward M-SEARCH requests like normal packets\n"
           "               proxy     Relay M-SEARCH requests via a local proxy\n"
           "                         socket. Replies to this local socket are\n"
           "                         forwarded to the original sender unmodified.\n"
           "               dial      Full SSDP/DIAL protocol proxy. Relay M-SEARCH\n"
           "                         requests via a local proxy socket. Replies\n"
           "                         are modified with the local address of\n"
           "                         Location Services and REST proxies.\n"
           "                         Used to support e.g. YouTube app on smart TV.\n"
           "           The search-term parameter can specify a M-SEARCH ST: header\n"
           "           value in which case the --msearch action will only apply to\n"
           "           that search-term. If no search-term is given this action\n"
           "           becomes the new default for packets with no matching ST.\n"
           "  --multicast IP   As well as listening for broadcasts the program\n"
           "                   will listen for and relay multicast packets\n"
           "                   using the specified multicast IP address(es).\n"
           "                   e.g. 224.0.0.251 - mDNS/Chromecast/Apple Bonjour\n"
           "                        239.255.255.250 - UPnP Discovery/SSDP\n"
           "                   This argument may be specified more than once.\n"
           "  --ttl-id|-t   Preserve DSCP and mark relayed packets by setting\n"
           "                the IP TTL header field to ID + %i. This is how the\n"
           "                original version of this tool operated by default.\n"
           "  --blockid ID  Block traffic relayed by another udpbroadcastrelay\n"
           "                instance with the specified ID. --blockid can be\n"
           "                specified multiple times to block more than one ID.\n"
           "  -d       Enables debugging. Specify twice for extra debug info.\n"
           "  -f       Forces forking to background. A PID file will be created\n"
           "           at /var/run/udpbroadcastrelay_ID.pid\n"
           "  --help|-h   Display this detailed help dialog.\n", TTL_ID_OFFSET);
}

int main(int argc,char **argv) {
    /* Debugging, forking, other settings */
    FILE *pidfp;
    int forking = 0;
    int use_ttl_id = 0;
    u_int16_t port = 0;
    u_char id = 0;
    char* multicastAddrs[MAXMULTICAST];
    int multicastAddrsNum = 0;
    char* interfaceNames[MAXIFS];
    int interfaceNamesNum = 0;
    int blockIDs[MAXBLOCKIDS];
    int numBlockIDs = 0;
    in_addr_t spoof_addr = 0;

    /* Address broadcast packet was sent from */
    struct sockaddr_in rcv_addr;
    struct msghdr rcv_msg;
    struct iovec iov;
    iov.iov_base = gram + HEADER_LEN;
    iov.iov_len = sizeof(gram) - HEADER_LEN - 1;
    u_char pkt_infos[16384];
    rcv_msg.msg_name = &rcv_addr;
    rcv_msg.msg_namelen = sizeof(rcv_addr);
    rcv_msg.msg_iov = &iov;
    rcv_msg.msg_iovlen = 1;
    rcv_msg.msg_control = pkt_infos;
    rcv_msg.msg_controllen = sizeof(pkt_infos);
    static char pidfile[128];

    int child_pid;
#ifndef HAVE_ARC4RANDOM
srandom(time(NULL) ^ getpid());
#endif



    if(argc < 2) {
        display_usage(stderr, argv[0]);
        exit(1);
    }

    int i;
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i],"-d") == 0) {
            debug++;
            if (debug == 1) {
                DPRINT ("udpbroadcastrelay v1.2.20 built on " __DATE__ " " __TIME__ "\n");
                DPRINT ("Debugging Mode enabled\n");
            }
        }
        if ((strcmp(argv[i], "--help") == 0) ||
            (strcmp(argv[i], "-h") == 0)) {
            display_usage(stdout, argv[0]);
            display_help(argv[0]);
            exit(0);
        }
    }

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i],"-d") == 0) {
            // Already handled
        } else if (strcmp(argv[i],"-f") == 0) {
            DPRINT ("Forking Mode enabled\n");
            forking = 1;
        }
        else if (strcmp(argv[i],"-s") == 0) {
            /* INADDR_NONE is a valid IP address (-1 = 255.255.255.255),
             * so inet_pton() would be a better choice. But in this case it
             * does not matter. */
            i++;
            spoof_addr = inet_addr(argv[i]);
            if (spoof_addr == INADDR_NONE) {
                fprintf (stderr,"invalid IP address: %s\n", argv[i]);
                exit(1);
            }
            DPRINT ("Outgoing source IP set to %s\n", argv[i]);
        }
        else if (strcmp(argv[i],"--id") == 0) {
            i++;
            id = atoi(argv[i]);
            DPRINT ("ID set to %i\n", id);
        }
        else if (strcmp(argv[i],"--blockid") == 0) {
            if (numBlockIDs >= MAXBLOCKIDS) {
                fprintf(stderr, "More than maximum %i block IDs specified.\n", MAXBLOCKIDS);
                exit(1);
            }
            i++;
            blockIDs[numBlockIDs] = atoi(argv[i]);
            numBlockIDs++;
        }
        else if (strcmp(argv[i],"--port") == 0) {
            i++;
            port = atoi(argv[i]);
            DPRINT ("Port set to %i\n", port);
        }
        else if (strcmp(argv[i],"--dev") == 0) {
            if (interfaceNamesNum >= MAXIFS) {
                fprintf(stderr, "More than %i interfaces specified.\n", MAXIFS);
                exit(1);
            }
            i++;
            interfaceNames[interfaceNamesNum] = argv[i];
            interfaceNamesNum++;
        }
        else if (strcmp(argv[i],"--multicast") == 0) {
            if (multicastAddrsNum >= MAXMULTICAST) {
                fprintf(stderr, "More than %i multicast addresses specified", MAXMULTICAST);
                exit(1);
            }
            i++;
            multicastAddrs[multicastAddrsNum] = argv[i];
            multicastAddrsNum++;
        }
        else if (strcmp(argv[i],"--msearch") == 0) {
            char* s;
            int action;
            int len;

            i++;
            len = strlen(argv[i]);
            s = strchr(argv[i],',');
            /* Check if an optional search string was specified for the msearch option */
            if (s) {
                len = s - argv[i];
                s++;
            }
            if (!strncmp("fwd",argv[i],len)) {
                action = MSEARCH_ACTION_FORWARD;
            }
            else if (!strncmp("block",argv[i],len)) {
                action = MSEARCH_ACTION_BLOCK;
            }
            else if (!strncmp("proxy",argv[i],len)) {
                action = MSEARCH_ACTION_PROXY;
            }
            else if (!strncmp("dial",argv[i],len)) {
                action = MSEARCH_ACTION_DIAL;
            }
            else {
                fprintf(stderr, "Unknown --msearch action %.*s specified\n", len, argv[i]);
                exit(1);
            }

            /* Default to DIAL protocol search term if dial action was specified with no search term */
            if ((action == MSEARCH_ACTION_DIAL) && (!s)) {
                s = "urn:dial-multiscreen-org:service:dial:1";
                DPRINT ("Set default M-SEARCH search term %s for the DIAL protocol\n", s);
            }
            /* Update search term filter list if a specific search term was specified */
            if (s) {
                if (num_msearch_filters >= MAX_MSEARCH_FILTERS) {
                    fprintf(stderr, "More than maximum of %i M-SEARCH filter terms specified\n", MAX_MSEARCH_FILTERS);
                    exit(1);
                }
                if (!*s) {
                    fprintf(stderr, "M-SEARCH search string filter can't be empty\n");
                    exit(1);
                }
                msearch_filters[num_msearch_filters].searchstring = s;
                msearch_filters[num_msearch_filters].action = action;
                num_msearch_filters++;
                DPRINT ("Added M-SEARCH filter %i: search term '%s' action %s\n", num_msearch_filters, s, get_msearch_action_name(action));
            }
            else {
                default_msearch_action= action;
                DPRINT ("Set default M-SEARCH action to %s\n", get_msearch_action_name(action));
            }
        }
        else if ((strcmp(argv[i], "--ttl-id") == 0) ||
                 (strcmp(argv[i], "-t") == 0)) {
            use_ttl_id = 1;
        }
        else if (strncmp(argv[i], "-", 1) == 0) {
            fprintf (stderr, "Unknown arg: %s\n", argv[i]);
            exit(1);
        }
        else {
            break;
        }
    }

    if (numBlockIDs) {
        DPRINT ("Blocking traffic from ID(s) %i", blockIDs[0]);
        for (i = 1; i < numBlockIDs; i++) {
            DPRINT (", %i", blockIDs[i]);
        }
        DPRINT ("\n");
    }
    
    if (id < 1 || id > MAXID)
    {
        fprintf (stderr,"ID argument %i not between 1 and %i\n", id, MAXID);
        exit(1);
    }
    if (port < 1 || port > 65535) {
        fprintf (stderr,"Port argument not valid\n");
        exit(1);
    }

    u_char ttl = 0;
    u_char tos = 0;
    if (use_ttl_id) {
        ttl = id + TTL_ID_OFFSET;
        DPRINT ("ID: %i (ttl: %i), Port %i\n",id,ttl,port);
    } else {
        /*
         * DSCP occupies the most significant 6 bits of the IP
         * TOS field. We do not use the remaining 2 bits (ECN)
         * because there are reports that in rare cases hosts
         * can react poorly to these being set spuriously.
         */
        tos = id << 2;
        DPRINT ("ID: %i (DSCP: %i, ToS: 0x%02x), Port %i\n", id, id,
                tos, port);
    }



    /* We need to find out what IP's are bound to this host - set up a temporary socket to do so */
    int fd;
     if((fd=socket(AF_INET,SOCK_RAW,IPPROTO_RAW)) < 0)
    {
          perror("socket");
        fprintf(stderr,"You must be root to create a raw socket\n");
          exit(1);
      };


    /* For each interface on the command line */
    for (int i = 0; i < interfaceNamesNum; i++) {
        struct Iface* iface = &ifs[maxifs];

        struct ifreq basereq;
        strncpy(basereq.ifr_name,interfaceNames[i],IFNAMSIZ);

        /* Save interface name for debug output */
        iface->ifname = interfaceNames[i];

        /* Request index for this interface */
        {
            #ifdef ___APPLE__
                /*
                TODO: Supposedly this works for all OS, including non-Apple,
                and could replace the code below
                */
                iface->ifindex = if_nametoindex(interfaceNames[i]);
            #else
                struct ifreq req;
                memcpy(&req, &basereq, sizeof(req));
                if (ioctl(fd,SIOCGIFINDEX, &req) < 0) {
                    perror("ioctl(SIOCGIFINDEX)");
                    exit(1);
                }
                #ifdef __FreeBSD__
                iface->ifindex = req.ifr_index;
                #else
                iface->ifindex = req.ifr_ifindex;
                #endif
            #endif
        }

        /* Request flags for this interface */
        short ifFlags;
        {
            struct ifreq req;
            memcpy(&req, &basereq, sizeof(req));
            if (ioctl(fd,SIOCGIFFLAGS, &req) < 0) {
                perror("ioctl(SIOCGIFFLAGS)");
                exit(1);
            }
            ifFlags = req.ifr_flags;
        }

        /* if the interface is not up or a loopback, ignore it */
        if ((ifFlags & IFF_UP) == 0 || (ifFlags & IFF_LOOPBACK)) {
            continue;
        }

        /* Get local IP for interface */
        {
            struct ifreq req;
            memcpy(&req, &basereq, sizeof(req));
            if (ioctl(fd,SIOCGIFADDR, &req) < 0) {
                perror("ioctl(SIOCGIFADDR)");
                exit(1);
            }
            memcpy(
                &iface->ifaddr,
                &((struct sockaddr_in *)&req.ifr_addr)->sin_addr,
                sizeof(struct in_addr)
            );
        }

        /* Get broadcast address for interface */
        {
            struct ifreq req;
            memcpy(&req, &basereq, sizeof(req));
            if (ifFlags & IFF_BROADCAST) {
                if (ioctl(fd,SIOCGIFBRDADDR, &req) < 0) {
                    perror("ioctl(SIOCGIFBRDADDR)");
                    exit(1);
                }
                memcpy(
                    &iface->dstaddr,
                    &((struct sockaddr_in *)&req.ifr_broadaddr)->sin_addr,
                    sizeof(struct in_addr)
                );
            } else {
                if (ioctl(fd,SIOCGIFDSTADDR, &req) < 0) {
                    perror("ioctl(SIOCGIFBRDADDR)");
                    exit(1);
                }
                memcpy(
                    &iface->dstaddr,
                    &((struct sockaddr_in *)&req.ifr_dstaddr)->sin_addr,
                    sizeof(struct in_addr)
                );
            }
        }

        char ifaddr[255];
        inet_ntoa2(iface->ifaddr, ifaddr, sizeof(ifaddr));
        char dstaddr[255];
        inet_ntoa2(iface->dstaddr, dstaddr, sizeof(dstaddr));

        DPRINT(
            "%s: %i / %s / %s\n",
            basereq.ifr_name,
            iface->ifindex,
            ifaddr,
            dstaddr
        );

        // Set up a one raw socket per interface for sending our packets through
        if((iface->raw_socket = socket(AF_INET,SOCK_RAW,IPPROTO_RAW)) < 0) {
            perror("socket");
            exit(1);
        }
        {
            int yes = 1;
            #ifdef __FreeBSD__
                int no = 0;
            #endif
            if (setsockopt(iface->raw_socket, SOL_SOCKET, SO_BROADCAST, &yes, sizeof(yes))<0) {
                perror("setsockopt SO_BROADCAST");
                exit(1);
            }
            if (setsockopt(iface->raw_socket, IPPROTO_IP, IP_HDRINCL, &yes, sizeof(yes))<0) {
                perror("setsockopt IP_HDRINCL");
                exit(1);
            }
            if (setsockopt(iface->raw_socket, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(yes))<0) {
                perror("setsockopt SO_REUSEPORT");
                exit(1);
            }
            #ifdef __FreeBSD__
                if((setsockopt(iface->raw_socket, IPPROTO_IP, IP_MULTICAST_LOOP, &no, sizeof(no))) < 0) {
                    perror("setsockopt IP_MULTICAST_LOOP");
                }
                if((setsockopt(iface->raw_socket, IPPROTO_IP, IP_MULTICAST_IF, &iface->ifaddr, sizeof(iface->ifaddr))) < 0) {
                    perror("setsockopt IP_MULTICAST_IF");
                }
                if (use_ttl_id) {
                    int setttl = ttl;
                    if((setsockopt(iface->raw_socket, IPPROTO_IP, IP_MULTICAST_TTL, &setttl, sizeof(setttl))) < 0) {
                        perror("setsockopt IP_MULTICAST_TTL");
                    }
                }
            #else
                // bind socket to dedicated NIC (override routing table)
                if (setsockopt(iface->raw_socket, SOL_SOCKET, SO_BINDTODEVICE, interfaceNames[i], strlen(interfaceNames[i])+1)<0)
                {
                    perror("setsockopt SO_BINDTODEVICE");
                    exit(1);
                };
            #endif
        }

        /* ... and count it */
        maxifs++;
    }

    DPRINT("found %i interfaces total\n",maxifs);

    /* Free our allocated buffer and close the socket */
    close(fd);

    /* Create our broadcast receiving socket */
    int rcv;
    {
        if((rcv=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP)) < 0)
          {
              perror("socket");
              exit(1);
          }
        int yes = 1;
        if(setsockopt(rcv, SOL_SOCKET, SO_BROADCAST, &yes, sizeof(yes))<0){
            perror("SO_BROADCAST on rcv");
            exit(1);
        };
        if (setsockopt(rcv, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(yes))<0) {
            perror("SO_REUSEPORT on rcv");
            exit(1);
        }
        #ifdef __FreeBSD__
            if(setsockopt(rcv, IPPROTO_IP, IP_RECVTTL, &yes, sizeof(yes))<0){
                perror("IP_RECVTTL on rcv");
                exit(1);
            };
            if(setsockopt(rcv, IPPROTO_IP, IP_RECVTOS, &yes, sizeof(yes))<0){
                perror("IP_RECVTOS on rcv");
                exit(1);
            };
            if(setsockopt(rcv, IPPROTO_IP, IP_RECVIF, &yes, sizeof(yes))<0){
                perror("IP_RECVIF on rcv");
                exit(1);
            };
            if(setsockopt(rcv, IPPROTO_IP, IP_RECVDSTADDR, &yes, sizeof(yes))<0){
                perror("IP_RECVDSTADDR on rcv");
                exit(1);
            };
        #else
            if(setsockopt(rcv, SOL_IP, IP_RECVTTL, &yes, sizeof(yes))<0){
                perror("IP_RECVTTL on rcv");
                exit(1);
            };
            if(setsockopt(rcv, SOL_IP, IP_RECVTOS, &yes, sizeof(yes))<0){
                perror("IP_RECVTOS on rcv");
                exit(1);
            };
            if(setsockopt(rcv, SOL_IP, IP_PKTINFO, &yes, sizeof(yes))<0){
                perror("IP_PKTINFO on rcv");
                exit(1);
            };
        #endif
        for (int i = 0; i < multicastAddrsNum; i++) {
            for (int x = 0; x < maxifs; x++) {
                struct ip_mreq mreq;
                memset(&mreq, 0, sizeof(struct ip_mreq));
                mreq.imr_interface.s_addr = ifs[x].ifaddr.s_addr;
                mreq.imr_multiaddr.s_addr = inet_addr(multicastAddrs[i]);
                DPRINT("IP_ADD_MEMBERSHIP:\t\t%s %s\n",inet_ntoa(ifs[x].ifaddr),multicastAddrs[i]);
                if(setsockopt(rcv, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq))<0){
                    perror("IP_ADD_MEMBERSHIP on rcv");
                    exit(1);
                }
            }
        }

        struct sockaddr_in bind_addr;
        bind_addr.sin_family = AF_INET;
        bind_addr.sin_port = htons(port);
        bind_addr.sin_addr.s_addr = INADDR_ANY;
        if(bind(rcv, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
            perror("bind");
            fprintf(stderr,"rcv bind\n");
            exit(1);
        }
    }


    DPRINT("Done Initializing\n\n");
    sprintf(pidfile,"/var/run/udpbroadcastrelay_%d.pid",id);
    if ((pidfp = fopen(pidfile, "w")) != NULL) {
    fprintf(pidfp, "%d\n", getpid());
    fclose(pidfp);
    strcpy(g_pidfile,pidfile);
    }
    /* Fork to background */
    if (! debug) {
        if (forking && (child_pid=fork())) {
            sprintf(pidfile,"/var/run/udpbroadcastrelay_%d.pid",id);
            if ((pidfp = fopen(pidfile, "w")) != NULL) {
            fprintf(pidfp, "%d\n", child_pid);
            fclose(pidfp);
            strcpy(g_pidfile,pidfile);
        }

        exit(0);
        fclose(stdin);
        fclose(stdout);
        fclose(stderr);
        }
    }

    for (;;) /* endless loop */
    {
        catch_sigterm();

        // Wait for message on main receive socket while servicing proxy connections
        service_proxy_messages(rcv);

        /* Receive a broadcast packet */
        int len = recvmsg(rcv,&rcv_msg,0);
        if (len <= 0) continue;    /* ignore broken packets */

        /* Find the ToS, ttl and the receiving interface */
        struct cmsghdr *cmsg;
        int rcv_ttl = 0;
        int rcv_tos = 0;
        int found_rcv_tos = 0;
        int rcv_ifindex = 0;
        struct in_addr rcv_inaddr;
        int foundRcvIf = 0;
        int foundRcvIp = 0;
        if (rcv_msg.msg_controllen > 0) {
            for (cmsg=CMSG_FIRSTHDR(&rcv_msg);cmsg;cmsg=CMSG_NXTHDR(&rcv_msg,cmsg)) {
                #ifdef __FreeBSD__
                    if (cmsg->cmsg_type==IP_RECVTTL) {
                        rcv_ttl = *(int *)CMSG_DATA(cmsg);
                    }
                    if (cmsg->cmsg_type==IP_RECVTOS) {
                        rcv_tos = *(int *)CMSG_DATA(cmsg);
                        found_rcv_tos = 1;
                    }
                    if (cmsg->cmsg_type==IP_RECVDSTADDR) {
                        rcv_inaddr=*((struct in_addr *)CMSG_DATA(cmsg));
                        foundRcvIp = 1;
                    }
                    if (cmsg->cmsg_type==IP_RECVIF) {
                        rcv_ifindex=((struct sockaddr_dl *)CMSG_DATA(cmsg))->sdl_index;
                        foundRcvIf = 1;
                    }
                #else
                    if (cmsg->cmsg_type==IP_TTL) {
                        rcv_ttl = *(int *)CMSG_DATA(cmsg);
                    }
                    if (cmsg->cmsg_type==IP_TOS) {
                        rcv_tos = *(int *)CMSG_DATA(cmsg);
                        found_rcv_tos = 1;
                    }
                    if (cmsg->cmsg_type==IP_PKTINFO) {
                        rcv_ifindex=((struct in_pktinfo *)CMSG_DATA(cmsg))->ipi_ifindex;
                        foundRcvIf = 1;
                        rcv_inaddr=((struct in_pktinfo *)CMSG_DATA(cmsg))->ipi_addr;
                        foundRcvIp = 1;
                    }
                #endif
            }
        }

        if (!foundRcvIp) {
            perror("Source IP not found on incoming packet\n");
            continue;
        }
        if (!foundRcvIf) {
            perror("Interface not found on incoming packet\n");
            continue;
        }
        if (!rcv_ttl) {
            perror("TTL not found on incoming packet\n");
            continue;
        }
        if (!found_rcv_tos) {
            if (use_ttl_id) {
                /*
                 * If we're not using DSCP as the tag field then
                 * this error doesn't matter but print the warning
                 * anyway.
                 */
                perror("Warning : ToS not found on incoming packet - continuing processing\n");
            } else {
                perror("ToS not found on incoming packet\n");
                continue;
            }
        }

        struct Iface* fromIface = NULL;
        for (int iIf = 0; iIf < maxifs; iIf++) {
            if (ifs[iIf].ifindex == rcv_ifindex) {
                fromIface = &ifs[iIf];
            }
        }

        struct in_addr origFromAddress = rcv_addr.sin_addr;
        u_short origFromPort = ntohs(rcv_addr.sin_port);
        struct in_addr origToAddress = rcv_inaddr;
        u_short origToPort = port;
        u_short proxyPort;

        // Ensure received datagram is always NULL terminated, makes it
        // easier to use string functions on the datagram.
        gram[HEADER_LEN + len] = 0;

        char origFromAddressStr[255];
        inet_ntoa2(origFromAddress, origFromAddressStr, sizeof(origFromAddressStr));
        char origToAddressStr[255];
        inet_ntoa2(origToAddress, origToAddressStr, sizeof(origToAddressStr));
        DPRINTTIME;
        DPRINT("<- [ %s:%d -> %s:%d (iface=%s len=%i tos=0x%02x DSCP=%i ttl=%i)\n",
            origFromAddressStr, origFromPort,
            origToAddressStr, origToPort,
            ifname_from_idx(rcv_ifindex), len, rcv_tos,
            rcv_tos >> 2, rcv_ttl
        );

        if (use_ttl_id) {
            if (rcv_ttl == ttl) {
                DPRINT("IP TTL (%i) matches ID (%i) + %i. Packet Ignored.\n\n",
                       rcv_ttl, id, TTL_ID_OFFSET);
                continue;
            }
        } else {
            if ((rcv_tos & 0xfc) == tos) {
                DPRINT("IP DSCP (%i) matches ID. IP ToS 0x%02x. Packet Ignored.\n\n",
                       tos >> 2, tos);
                continue;
            }
        }

        if (numBlockIDs) {
            int rxid = (use_ttl_id) ? (rcv_ttl - TTL_ID_OFFSET) : (rcv_tos >> 2);
            for (i = 0; i < numBlockIDs; i++) {
                if (rxid == blockIDs[i])
                    break;
            }
            if (i < numBlockIDs) {
                DPRINT ("Packet ID %i matches a blocklist ID. Packet Ignored.\n\n", rxid);
                continue;
            }
        }

        if (!fromIface) {
            DPRINT("Not from managed iface\n\n");
            continue;
        }

        // Check if we need to perform special M-SEARCH request handling
        proxyPort = 0;
        if ((default_msearch_action != MSEARCH_ACTION_FORWARD) || num_msearch_filters) {
            if (!check_msearch_filters(origFromAddress, origFromPort, fromIface, &proxyPort))
                continue;
        }

        /* Iterate through our interfaces and send packet to each one */
        for (int iIf = 0; iIf < maxifs; iIf++) {
            struct Iface* iface = &ifs[iIf];

            /* no bounces, please */
            if (iface == fromIface) {
                continue;
            }

            struct in_addr fromAddress;
            u_short fromPort;
            if (spoof_addr == inet_addr("1.1.1.1")) {
                fromAddress = iface->ifaddr;
                fromPort = port;
            } else if (spoof_addr == inet_addr("1.1.1.2")) {
                fromAddress = iface->ifaddr;
                fromPort = origFromPort;
            } else if (spoof_addr) {
                fromAddress.s_addr = spoof_addr;
                fromPort = origFromPort;
            } else {
                fromAddress = origFromAddress;
                fromPort = origFromPort;
            }
            if (proxyPort) {
                fromAddress = iface->ifaddr;
                fromPort = proxyPort;
            }

            struct in_addr toAddress;
            if (rcv_inaddr.s_addr == INADDR_BROADCAST
                || rcv_inaddr.s_addr == fromIface->dstaddr.s_addr) {
                // Received on interface broadcast address -- rewrite to new interface broadcast addr
                toAddress = iface->dstaddr;
            } else {
                // Send to whatever IP it was originally to
                toAddress = rcv_inaddr;
            }
            u_short toPort = origToPort;

            char fromAddressStr[255];
            inet_ntoa2(fromAddress, fromAddressStr, sizeof(fromAddressStr));
            char toAddressStr[255];
            inet_ntoa2(toAddress, toAddressStr, sizeof(toAddressStr));
            DPRINTTIME;
            DPRINT (
                "-> [ %s:%d -> %s:%d (iface=%s len=%i ",
                fromAddressStr, fromPort,
                toAddressStr, toPort,
                ifname_from_idx(iface->ifindex), len);
            if (use_ttl_id) {
                DPRINT("tos=0x%02x DSCP=%i ttl=%i)\n",
                       rcv_tos, rcv_tos >> 2, ttl);
            } else {
                DPRINT("tos=0x%02x DSCP=%i ttl=%i)\n",
                       tos + (rcv_tos & 0x03), tos >> 2, rcv_ttl);
            }
            /* Send the packet */

            if (use_ttl_id) {
                /* Set IP TTL field */
                /* Note. The following statement has no effect on
                 * multicast packets, only on relayed broadcasts.
                 * For mcast packets we have to set socket
                 * option IP_MULTICAST_TTL to change TTL */
                gram[8] = ttl;
            } else {
                /*
                 * Set IP ToS byte so that DSCP = instance ID and ECN is
                 * preserved from the original packet.
                 */
                gram[1] = tos + (rcv_tos & 0x03);
                /* Set TTL to the same as the received packet */
                gram[8] = rcv_ttl;
                if((setsockopt(iface->raw_socket, IPPROTO_IP, IP_MULTICAST_TTL, &rcv_ttl, sizeof(rcv_ttl))) < 0) {
                    perror("setsockopt IP_MULTICAST_TTL");
                }
            }
            memcpy(gram+12, &fromAddress.s_addr, 4);
            memcpy(gram+16, &toAddress.s_addr, 4);
            *(u_short*)(gram+4)=htons(fragmentID++);
            *(u_short*)(gram+20)=htons(fromPort);
            *(u_short*)(gram+22)=htons(toPort);
            #if (defined __FreeBSD__ && __FreeBSD__ <= 10) || defined __APPLE__
            *(u_short*)(gram+24)=htons(UDPHEADER_LEN + len);
            *(u_short*)(gram+2)=HEADER_LEN + len;
            #else
            *(u_short*)(gram+24)=htons(UDPHEADER_LEN + len);
            *(u_short*)(gram+2)=htons(HEADER_LEN + len);
            #endif
            struct sockaddr_in sendAddr;
            sendAddr.sin_family = AF_INET;
            sendAddr.sin_port = htons(toPort);
            sendAddr.sin_addr = toAddress;

            if (sendto(
                iface->raw_socket,
                &gram,
                HEADER_LEN+len,
                0,
                (struct sockaddr*)&sendAddr,
                sizeof(sendAddr)
            ) < 0) {
                perror("sendto");
            }
        }
        DPRINT ("\n");
    }
};
