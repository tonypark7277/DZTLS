GETDNS_CFLAGS := $(shell pkg-config --cflags getdns)
GETDNS_LIBS   := $(shell pkg-config --libs getdns)

ztls_tfo_getdns_client: echo_client_getdns.c
	gcc -g $(GETDNS_CFLAGS) -o ztls_tfo_getdns_client echo_client_getdns.c \
	    $(GETDNS_LIBS) -lssl -lcrypto -lresolv -pthread -DMODE=3

ztls_tcp_getdns_client: echo_client_getdns.c
	gcc -g $(GETDNS_CFLAGS) -o ztls_tcp_getdns_client echo_client_getdns.c \
	    $(GETDNS_LIBS) -lssl -lcrypto -lresolv -pthread -DMODE=2

tls_tcp_getdns_client: echo_client_getdns.c
	gcc -g $(GETDNS_CFLAGS) -o tls_tcp_getdns_client echo_client_getdns.c \
	    $(GETDNS_LIBS) -lssl -lcrypto -lresolv -pthread -DMODE=0

server: echo_mpserv.c
	gcc -o server echo_mpserv.c -lssl -lcrypto

all: ztls_tfo_getdns_client ztls_tcp_getdns_client tls_tcp_getdns_client

clean:
	rm -f server ztls_tfo_getdns_client ztls_tcp_getdns_client tls_tcp_getdns_client
