GETDNS_CFLAGS := $(shell pkg-config --cflags getdns)
GETDNS_LIBS   := $(shell pkg-config --libs getdns)

ztls_tfo_client: echo_client.c
	gcc -g $(GETDNS_CFLAGS) -o ztls_tfo_client echo_client.c \
	    $(GETDNS_LIBS) -lssl -lcrypto -lresolv -pthread -DMODE=3

ztls_tcp_client: echo_client.c 
	gcc -g $(GETDNS_CFLAGS) -o ztls_tcp_client echo_client.c \
	    $(GETDNS_LIBS) -lssl -lcrypto -lresolv -pthread -DMODE=2

tls_tfo_client: echo_client.c 
	gcc $(GETDNS_CFLAGS) -o tls_tfo_client echo_client.c \
	    $(GETDNS_LIBS) -lssl -lcrypto -lresolv -pthread -DMODE=1

tls_tcp_client: echo_client.c
	gcc $(GETDNS_CFLAGS) -o tls_tcp_client echo_client.c \
	    $(GETDNS_LIBS) -lssl -lcrypto -lresolv -pthread -DMODE=0

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

all: ztls_tfo_client ztls_tcp_client tls_tfo_client tls_tcp_client server ztls_tfo_getdns_client ztls_tcp_getdns_client tls_tcp_getdns_client

clean:
	rm -f ztls_tfo_client ztls_tcp_client tls_tfo_client tls_tcp_client server ztls_tfo_getdns_client ztls_tcp_getdns_client tls_tcp_getdns_client