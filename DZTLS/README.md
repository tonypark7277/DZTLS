Welcome to the aztls Project
==============================
The ztls is a project that provides example servers and clients that perform ztls handshake using ztlslib.
ztlslib (github.com/swlim02/ztlslib) is a library that implements ZTLS handshake based on OpenSSL. ZTLS leverages DNS to establish secure sessions with 0-RTT. For details, see 'ZTLS: A DNS-based Approach to Zero Round Trip Delay in TLS handshake' published in THE WEB CONFERENCE 2023.

# How to compile
> make ztls_tfo_client
> make ztls_tcp_client
> make tls_tfo_client
> make tls_tcp_client
> make server

# How to run 
> ./server [port]  
> ./[tls mode]_[tcp mode]_client [domain_address] [port]  
      [tls_mode] = ztls | tls
      [tcp_mode] = tfo  | tcp

# Prerequisite
install github.com/swlim02/ztlslib  
install github.com/tonypark7277/AZTLS_kernel  

# TroubleShooting
1. add environment variables
export LD_LIBRARY_PATH=/usr/local/lib

2. Enable TCP Fastopen using sysctl
> [sudo] sysctl -w net.ipv4.tcp_fastopen=3

3. Change IP address hardcoded in `create_socket_bio()` to your own IP address in little endian. \n
> uint64_t temp = 0xc4f6c92b; (43.201.246.196 -> 0x2b c9 f6 c4)

4. Install Systemd version 252


# Environment Setup
This program requires several DNS records. See an_example_of_DNSzonefile_for_ZTLS file for environment setup.
