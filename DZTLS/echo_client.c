#include "echo_client.h"

#include <arpa/nameser.h>
#include <netinet/in.h>
#include <resolv.h>
#include <string.h>
#include <pthread.h>
#include <netdb.h>

////////////////////////////////////////////////////////////////////////////////////////
//                            added for setting TCP FASTOPEN                          //
////////////////////////////////////////////////////////////////////////////////////////
#include <netinet/tcp.h>
#include <net/if.h>
#include <sys/ioctl.h>

#ifndef TCP_FASTOPEN_CONNECT
#define TCP_FASTOPEN_CONNECT 30
#endif
////////////////////////////////////////////////////////////////////////////////////////

#define BUF_SIZE 10000

#if MODE == 3
int DNS = 1; 
int TFO = 1;
#elif MODE == 2
int DNS = 1;
int TFO = 0;
#elif MODE == 1
int DNS = 0;
int TFO = 1;
#else
int DNS = 0;
int TFO = 0;
#endif
//  MODE = DNS TFO (2)
// 0 = false; //TFO or ZTLS would not be used
// 1 = true;  //TFO or ZTLS would be used

struct DNS_info{
    struct {
        time_t validity_period_not_before; //gmt unix time
        time_t validity_period_not_after;  //gmt unix time
        uint32_t dns_cache_id;
		uint32_t max_early_data_size;
    } DNSCacheInfo;
    struct {
        uint8_t *extension_type;
        uint16_t *extension_data;
    } EncryptedExtensions;
    struct {
        uint8_t group;
        EVP_PKEY *skey; // server's keyshare
    } KeyShareEntry;
    X509* cert; // server's cert
    struct {
        uint8_t certificate_request_context;
        uint16_t extensions;
    } CertRequest;
	/// added for aztls precookie;
	struct {
		uint64_t pre_cookie[4];
	} PreCookie;
    struct {
        uint16_t signature_algorithms;
        unsigned char cert_verify[BUF_SIZE]; // signature
    } CertVerifyEntry;
} dns_info;

static void init_openssl();
static int load_dns_info2(struct DNS_info* dp, char* truncated_dnsmsg_out, char* dnsmsg, char* ztls_cert, char* ztls_cert_orig);
static SSL_CTX *create_context();
static void keylog_callback(const SSL* ssl, const char *line);
static size_t resolve_hostname(const char *host, const char *port, struct sockaddr_storage *addr);
static void configure_connection(SSL *ssl);
static void error_handling(char *message);
static int dns_info_add_cb(SSL *s, unsigned int ext_type,
                    unsigned int context,
                    const unsigned char **out,
                    size_t *outlen, X509 *x, size_t chainidx,
                    int *al, void *arg);

static void dns_info_free_cb(SSL *s, unsigned int ext_type,
                     unsigned int context,
                     const unsigned char *out,
                     void *add_arg);

static int ext_parse_cb(SSL *s, unsigned int ext_type,
                        const unsigned char *in,
                        size_t inlen, int *al, void *parse_arg);
static time_t is_datetime(const char *datetime);

static void init_tcp_sync(char *argv[], struct DNS_info* dp, struct sockaddr_storage * addr, int sock, int * is_start, int * parsing_done);
static BIO *create_socket_bio(char *argv[], struct DNS_info *dp, int * is_start, int * parsing_done);
static void tlsa_query(char *argv[], unsigned char query_buffer[], int buffer_size, unsigned char ** tlsa_record_all, int * is_start);
unsigned char * hex_to_base64(unsigned char *hex0, int size, unsigned char hex[]);
struct arg_struct_bio {
	char ** argv;
	struct DNS_info * dp;
	int * is_start;
	int * parsing_done;
	BIO * bio;
};
struct arg_struct {
	char ** argv;
	struct DNS_info * dp;
	struct sockaddr_storage * addr;
	int sock;
	int * is_start;
	int * parsing_done;
};
struct arg_struct2 {
	char ** argv;
	unsigned char * query_buffer;
	int buffer_size;
	unsigned char ** tlsa_record_all;
	int * is_start;
};

static void *thread_create_socket_bio(void* arguments)
{
	struct arg_struct_bio * args = (struct arg_struct_bio *) arguments;
	args->bio = create_socket_bio(args->argv, args->dp, args->is_start, args->parsing_done);
	pthread_exit(NULL);
}

static void *thread_init_tcp_sync(void* arguments)
{
	struct arg_struct * args = (struct arg_struct *) arguments;
	init_tcp_sync(args->argv, args->dp, args->addr, args->sock, args->is_start, args->parsing_done);
	pthread_exit(NULL);
}

static void *thread_tlsa_query(void* arguments)
{
	struct arg_struct2 * args = (struct arg_struct2 *) arguments;
	tlsa_query(args->argv, args->query_buffer , args->buffer_size, args->tlsa_record_all, args->is_start);
	pthread_exit(NULL);
}

int main(int argc, char *argv[]){
	res_init();
	init_openssl();
	SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL) {
        error_handling("Failed to create the SSL_CTX\n");
    }
	// static ctx configurations 
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL); // SSL_VERIFY_NONE
	SSL_CTX_load_verify_locations(ctx, "./dns/cert/CarolCert.pem", "./dns/cert/");
	SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
	SSL_CTX_set_keylog_callback(ctx, keylog_callback);
	SSL_CTX_set_default_verify_paths(ctx);
	SSL * ssl = NULL;
	BIO * bio = NULL;

    if(argc != 3){
        printf("Usage : %s <port>\n", argv[0]);
        exit(1);
    }

	int sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(sock < 0){
        error_handling("socket() error");
    }

    char * ztls_cert;
    struct sockaddr_storage addr;
	char txt_record_except_signature[BUF_SIZE];
	char *txt_record_all;
	unsigned char *tlsa_record_all;
	char tlsa_record[BUF_SIZE];
	unsigned char query_buffer[4096];
	unsigned char query_buffer2[4096];
	unsigned char hex_buffer[2000] = "";
	unsigned char hex_out[2000];
	unsigned char hex_out_cert[4096] ="";
	int response;
	ns_type type;
	type= ns_t_txt;
	ns_msg nsMsg;
	ns_rr rr;

	int is_start = -1;
	int parsing_done = -1;

    // log
	printf("****start****\n");
	if (!DNS) {
    	struct timespec begin;
    	clock_gettime(CLOCK_MONOTONIC, &begin);
    	printf("start : %f\n",(begin.tv_sec) + (begin.tv_nsec) / 1000000000.0);
	}
	//=============================================================
	// Dynamic interaction start
	//=============================================================
    
	// get TXT record & dynamic ctx configurations for ZTLS
    if(DNS){
		_res.options = _res.options | RES_USE_EDNS0 ; 	// use EDNS0 
		// to avoid TCP retry after UDP failure
		// struct arg_struct args;
		// args.argv = argv;
		// args.dp = &dns_info;
		// args.addr = &addr;
		// args.sock = sock;
		// args.is_start = &is_start;
		// args.parsing_done = &parsing_done;

		struct arg_struct_bio args_bio;
		args_bio.argv = argv;
		args_bio.dp = &dns_info;
		args_bio.is_start = &is_start;
		args_bio.parsing_done = &parsing_done;

		pthread_t ptid;
		//pthread_create(&ptid, NULL, &thread_init_tcp_sync,(void *) &args);
		pthread_create(&ptid, NULL, &thread_create_socket_bio, (void *) &args_bio);

		struct arg_struct2 args2;
		args2.argv = argv;
		args2.query_buffer = query_buffer2;
		args2.buffer_size = sizeof(query_buffer2);
		args2.tlsa_record_all = &tlsa_record_all;
		args2.is_start = &is_start;

		pthread_t ptid2;
		pthread_create(&ptid2, NULL, &thread_tlsa_query, (void *) &args2);


		// A thread is created when a program is executed, and is executed when a user triggers
		sleep(1);
		struct timespec begin;
    	clock_gettime(CLOCK_MONOTONIC, &begin);
		is_start =1; //user trigger
    	printf("start : %f\n",(begin.tv_sec) + (begin.tv_nsec) / 1000000000.0);

		clock_gettime(CLOCK_MONOTONIC, &begin);
    	printf("start DNS TXT query: %f\n",(begin.tv_sec) + (begin.tv_nsec) / 1000000000.0);
		response = res_search(argv[1], C_IN, type, query_buffer, sizeof(query_buffer));
		// log
    	clock_gettime(CLOCK_MONOTONIC, &begin);
    	printf("complete DNS TXT query : %f\n",(begin.tv_sec) + (begin.tv_nsec) / 1000000000.0);
		if (response < 0) {
			printf("Error looking up service: TXT");
			return 2;
		}    
		ns_initparse(query_buffer, response, &nsMsg);
		ns_parserr(&nsMsg, ns_s_an, 0, &rr);
		u_char const *rdata = (u_char*)(ns_rr_rdata(rr)+1 );
		txt_record_all=(char*)rdata;
		txt_record_all[strlen((char*)rdata)] = '\0';


		pthread_join(ptid2, NULL);
		unsigned char * based64_out;
		based64_out = hex_to_base64(tlsa_record_all, 879, hex_buffer);
		char newline2[4] = "\n";
		for(int j = 0; j < 1172-64 ; j=j+64){
			strncat(hex_out_cert,based64_out+j,64);
			strcat(hex_out_cert,newline2);
		}
		strcat(hex_out_cert,based64_out+1152);
		strcat(hex_out_cert,newline2);
		ztls_cert = hex_out_cert;	

        load_dns_info2(&dns_info, txt_record_except_signature, txt_record_all, ztls_cert, based64_out); 
		parsing_done = 1; // indicate parsing zdata is done!
		SSL_CTX_add_custom_ext(ctx, 53, SSL_EXT_CLIENT_HELLO, dns_info_add_cb, dns_info_free_cb,NULL, NULL,NULL);// extentionTye = 53, Extension_data = dns_cache_id
    	if(dns_info.KeyShareEntry.group == 29){  // keyshare group : 0x001d(X25519)
			SSL_CTX_set1_groups_list(ctx, "X25519");
			// for demo, we will add other groups later.
			// switch 
			// P-256, P-384, P-521, X25519, X448, ffdhe2048, ffdhe3072, ffdhe4096, ffdhe6144, ffdhe8192
    	}
    	ssl = SSL_new(ctx);
    	SSL_set_wfd(ssl, DNS); // fd : 1 => ZTLS, fd : 0 => TLS 1.3
        // Check timestamp Valid
    	if(dns_info.DNSCacheInfo.validity_period_not_before < time(NULL) && dns_info.DNSCacheInfo.validity_period_not_after > time(NULL)){
        	printf("Valid Period\n");
    	}else{
       	 	printf("Not Valid Period\n");
    	}
		SSL_use_PrivateKey(ssl, dns_info.KeyShareEntry.skey); // set server's keyshare // this function is modified 
        SSL_use_certificate(ssl, dns_info.cert); // set sever's cert and verify cert_chain // this function is modified
    	if(dns_info.CertVerifyEntry.signature_algorithms == 2052)     //rsa pss rsae sha256 0x0804
		{
			strcat(txt_record_except_signature, "\n");
			strcat(dns_info.CertVerifyEntry.cert_verify, "\n");
			SSL_export_keying_material(ssl, (unsigned char*) txt_record_except_signature, 0, NULL, 0,
				 dns_info.CertVerifyEntry.cert_verify, BUF_SIZE, 0); // cert verify: signature of DNS cache info check. // this function is modified
		}	// for demo, we will only support rsa pss rsae_sha256
		pthread_join(ptid, NULL);
		if (args_bio.bio == NULL)
			error_handling("thread_create_socket_bio() error!\n");
		bio = args_bio.bio;
		SSL_set_bio(ssl, bio, bio);
		//SSL_set_fd(ssl, sock);
   }else {
		is_start = 1;
		parsing_done = 1;
		ssl = SSL_new(ctx);
		// fd : 1 => ZTLS, fd : 0 => TLS 1.3
		SSL_set_wfd(ssl, DNS);
		bio = create_socket_bio(argv, &dns_info, &is_start, &parsing_done);
		if (bio == NULL)
			error_handling("create_socket_bio() error!\n");
		SSL_set_bio(ssl, bio, bio);
	}
	// threads join

    /*
     * handshake start
     */
    configure_connection(ssl); // SSL do handshake
    char message[BUF_SIZE];
    int str_len;
    struct timespec send_ctos, receive_ctos;

    if(!DNS){ // normal TLS 1.3
        memcpy(message, "hello\n", 6);
        
		SSL_write(ssl, message, strlen(message));
		clock_gettime(CLOCK_MONOTONIC, &send_ctos);
		printf("send : %s", message);
		printf("%f\n",(send_ctos.tv_sec) + (send_ctos.tv_nsec) / 1000000000.0);
				
		if((str_len = SSL_read(ssl, message, BUF_SIZE-1))<=0){
			printf("error\n");
		}
		message[str_len] = 0;
		clock_gettime(CLOCK_MONOTONIC, &receive_ctos);
		printf("Message from server: %s", message);
		printf("receiving application data from server : %f\n",(receive_ctos.tv_sec) + (receive_ctos.tv_nsec) / 1000000000.0);
    }

    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    EVP_cleanup();
    return 0;
}

static BIO *create_socket_bio(char *argv[], struct DNS_info *dp, int * is_start, int * parsing_done){
	while (*is_start < 0) { //for prototype. next, use signal
		//nothing
	}

	BIO *bio = NULL;
	int sock = -1;
	BIO_ADDRINFO *res;
	const BIO_ADDRINFO *ai = NULL;

	struct timespec begin1, begin2;
    clock_gettime(CLOCK_MONOTONIC, &begin1);
	printf("start A and AAAA DNS records query : %f\n",(begin1.tv_sec) + (begin1.tv_nsec) / 1000000000.0);
	if (!BIO_lookup_ex(argv[1], argv[2], BIO_LOOKUP_CLIENT, AF_INET, SOCK_STREAM, 0, &res))
		error_handling("fail to transform address");
    clock_gettime(CLOCK_MONOTONIC, &begin2);
    printf("complete A and AAAA DNS records query : %f\n",(begin2.tv_sec) + (begin2.tv_nsec) / 1000000000.0);

	for (ai = res; ai != NULL; ai = BIO_ADDRINFO_next(ai)) {
		sock = BIO_socket(BIO_ADDRINFO_family(ai), SOCK_STREAM, 0, 0);
		if (sock == -1)
			continue;

		if (TFO) {
			if (DNS) {
				while (*parsing_done < 0) { // waiting for dns parsing done;
					//nothing
				}

				uint64_t temp = 0xaa5fd10d;//0xc4f6c92b;
				//0d.d1.5f.aa (0x0dd15faa)

				// memcpy(&temp, &(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr), 4);
				dp->PreCookie.pre_cookie[0] += temp << 32;
				// 0x6a7d2e93cc9ec183, 0xf88b08674705e42b, 0x5dad9dfec4d00ec1, 0x02a4ab1561953e1a
				// my ip: 147.46.125.106 --> 93.2e.7d.6a (0x932e7d6a)
				// my ip: 43.201.246.196 --> 2b.c9.f6.c4 (0x2bc9f6c4)

				setsockopt(sock, SOL_TCP, TCP_FASTOPEN_KEY, dp->PreCookie.pre_cookie, sizeof(dp->PreCookie.pre_cookie));
			}

			int opt = 1;
			if (setsockopt(sock, IPPROTO_TCP, TCP_FASTOPEN_CONNECT, &opt, sizeof(opt)) < 0) {
				error_handling("setsockopt() error!");
			}
		}

		if (!BIO_connect(sock, BIO_ADDRINFO_address(ai), BIO_SOCK_NODELAY)) {
			BIO_closesocket(sock);
			sock = -1;
			continue;
		}

		break;
	}

	BIO_ADDRINFO_free(res);

	if (sock == -1)
		error_handling("connect() error!");
	
	clock_gettime(CLOCK_MONOTONIC, &begin2);
	printf("complete TCP Sync : %f\n",(begin2.tv_sec) + (begin2.tv_nsec) / 1000000000.0);
	
	bio = BIO_new(BIO_s_socket());
	if (bio == NULL) {
		BIO_closesocket(sock);
		error_handling("BIO_new() error!");
	}

	BIO_set_fd(bio, sock, BIO_CLOSE);
	return bio;
}

static void init_tcp_sync(char *argv[], struct DNS_info* dp, struct sockaddr_storage * addr, int sock, int * is_start, int *parsing_done) {
	while(*is_start < 0) { //for prototyping. next, use signal.
		//nothing
	}
    struct timespec begin1, begin2;
    clock_gettime(CLOCK_MONOTONIC, &begin1);
    printf("start A and AAAA DNS records query : %f\n",(begin1.tv_sec) + (begin1.tv_nsec) / 1000000000.0);
    size_t len = resolve_hostname(argv[1], argv[2], addr);
    clock_gettime(CLOCK_MONOTONIC, &begin2);
    printf("complete A and AAAA DNS records query : %f\n",(begin2.tv_sec) + (begin2.tv_nsec) / 1000000000.0);


	////////////////////////////////////////////////////////////////////////////////////////
	//                            added for setting TCP FASTOPEN                          //
	////////////////////////////////////////////////////////////////////////////////////////
	if (TFO) {
		if (DNS) {
			// int search_fd;
			// struct ifreq ifr;

			// search_fd = socket(AF_INET, SOCK_DGRAM, 0);
			// ifr.ifr_addr.sa_family = AF_INET;

			// strncpy(ifr.ifr_name, "enp2s0", IFNAMSIZ-1);

			// ioctl(search_fd, SIOCGIFADDR, &ifr);
			// close(search_fd);

			while(*parsing_done < 0) { // waiting for dns parsing done;
			// nothing
			}

			uint64_t temp = 0xaa5fd10d;
			//memcpy(&temp, &(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr), 4);
			dp->PreCookie.pre_cookie[0] += temp << 32;
			// 0x6a7d2e93cc9ec183, 0xf88b08674705e42b, 0x5dad9dfec4d00ec1, 0x02a4ab1561953e1a
			// my ip: 147.46.125.106 --> 93.2e.7d.6a (0x932e7d6a)
			setsockopt(sock, SOL_TCP, TCP_FASTOPEN_KEY, dp->PreCookie.pre_cookie, sizeof(dp->PreCookie.pre_cookie));
		}

		int opt = 1;
		if (setsockopt(sock, IPPROTO_TCP, TCP_FASTOPEN_CONNECT, &opt, sizeof(opt)) < 0) {
			error_handling("setsockopt() error!");
		}
	}
	////////////////////////////////////////////////////////////////////////////////////////
	if(connect(sock, (struct sockaddr*) addr, len) < 0){
        error_handling("connect() error!");
    }else{
		clock_gettime(CLOCK_MONOTONIC, &begin2);
		printf("complete TCP Sync : %f\n",(begin2.tv_sec) + (begin2.tv_nsec) / 1000000000.0);
	}
}

static void tlsa_query(char *argv[], unsigned char query_buffer[], int buffer_size, unsigned char ** tlsa_record_all, int * is_start) {
	
	while(*is_start < 0) { //for prototyping. next, use signal.
		//nothing
	}

	char query_url[100] = "_443._tcp.";
	strcat(query_url,argv[1]);
	ns_type type2;
	type2 = ns_t_tlsa; 
	ns_msg nsMsg;
	ns_rr rr;
	int response;
	struct timespec begin;
	clock_gettime(CLOCK_MONOTONIC, &begin);
	printf("start DNS TLSA query: %f\n",(begin.tv_sec) + (begin.tv_nsec) / 1000000000.0);
	response = res_search(query_url, C_IN, type2, query_buffer, buffer_size);
	// log
	clock_gettime(CLOCK_MONOTONIC, &begin);
	printf("complete DNS TLSA query : %f\n",(begin.tv_sec) + (begin.tv_nsec) / 1000000000.0);
	if (response < 0) {
		printf("Error looking up service: TLSA");
	}    
	ns_initparse(query_buffer, response, &nsMsg);
	ns_parserr(&nsMsg, ns_s_an, 0, &rr);
	u_char const *rdata = (u_char*)(ns_rr_rdata(rr)+3 );
	
	*tlsa_record_all = (unsigned char*)rdata;
}
static void init_openssl(){
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
}

static int load_dns_info2(struct DNS_info* dp, char* truncated_dnsmsg_out, char* dnsmsg, char * ztls_cert, char * ztls_cert_orig){
    BIO *bio_key, *bio_cert;
    char *tmp;
	char publickey_prefix[150] = "-----BEGIN PUBLIC KEY-----\n";
	char publickey_postfix[30] = "\n-----END PUBLIC KEY-----\n";
	char certificate_prefix[BUF_SIZE] = "-----BEGIN CERTIFICATE-----\n";
	char certificate_postfix[30] = "-----END CERTIFICATE-----\n";
	char certificate_prefix2[BUF_SIZE] = "-----BEGIN CERTIFICATE-----\n";
	char certificate_postfix2[30] = "-----END CERTIFICATE-----\n";
	char txt_record_signature[BUF_SIZE];
	char newline[4] = "\n";
	char pre_cookie_tok[20] = "";
	char * ztls_version = "v=ztls1";

	//v=ztls1 check
	tmp = strtok(dnsmsg," ");
	strcat(truncated_dnsmsg_out,tmp);
	strtok(NULL, " ");//" "
	if(0!=strcmp(tmp,ztls_version)){
		printf("DNS TXT record's ZTLS version error\n");
	}
    
	// load dns cache info
	tmp = strtok(NULL," ");
	strcat(truncated_dnsmsg_out,tmp);
    dp->DNSCacheInfo.validity_period_not_before = is_datetime(tmp);
	printf("DNS cache period: %s~", tmp);
	strtok(NULL," ");
	tmp = strtok(NULL," ");
	strcat(truncated_dnsmsg_out,tmp);
    dp->DNSCacheInfo.validity_period_not_after = is_datetime(tmp);
	printf("~%s\n", tmp);
	strtok(NULL," ");
	tmp = strtok(NULL," ");
	strcat(truncated_dnsmsg_out,tmp);
	dp->DNSCacheInfo.max_early_data_size = strtoul(tmp, NULL, 0);
	strtok(NULL," ");
	tmp = strtok(NULL," ");
	strcat(truncated_dnsmsg_out,tmp);
    dp->DNSCacheInfo.dns_cache_id  = strtoul(tmp, NULL, 0);
	strtok(NULL," ");

	// load keyshare entry
	tmp = strtok(NULL," ");
	strcat(truncated_dnsmsg_out,tmp);
    dp->KeyShareEntry.group = strtoul(tmp, NULL, 0);
    bio_key = BIO_new(BIO_s_mem());
	strtok(NULL," ");
	tmp = strtok(NULL," ");
	strcat(truncated_dnsmsg_out,tmp);
	strcat(publickey_prefix, tmp);
	strcat(publickey_prefix, publickey_postfix);
    BIO_puts(bio_key, publickey_prefix);
    PEM_read_bio_PUBKEY(bio_key, &(dp->KeyShareEntry.skey), NULL, NULL);

	// load certificate
	char * begin_cert = "B_CERTIFICATE";
	char * end_cert = "E_CERTIFICATE";

	strcat(truncated_dnsmsg_out,begin_cert);
	strcat(truncated_dnsmsg_out,ztls_cert_orig);
	strcat(truncated_dnsmsg_out,end_cert);
	strcat(certificate_prefix2, ztls_cert);
	strcat(certificate_prefix2, certificate_postfix2);

    bio_cert = BIO_new(BIO_s_mem());
    BIO_puts(bio_cert, certificate_prefix2);
    PEM_read_bio_X509(bio_cert, &(dp->cert), NULL, NULL);

// Client Certificate Request Check
// for demo No Client Certificate Request
	strtok(NULL," ");
	tmp = strtok(NULL," ");
	strcat(truncated_dnsmsg_out,tmp);
	printf("Client Certificate Request: %s\n", tmp);
	
//  Check AZTLS pre-cookie for tcp fastopen
//  for demo, it is determined as following:
//	00000000cc9ec183f88b08674705e42b5dad9dfec4d00ec102a4ab1561953e1a
    strtok(NULL, " ");
	tmp = strtok(NULL, " ");
	strcat(truncated_dnsmsg_out, tmp);
	for (int i = 0; i < 4; i++) {
		strcpy(pre_cookie_tok, "0x");
		strncat(pre_cookie_tok, tmp+16*i, 16);
		dp->PreCookie.pre_cookie[i] = strtoul(pre_cookie_tok, NULL, 16);
	}

//  load Signature algorithm used to sign z-data
//	for demo, signature algorithm = 2052
	strtok(NULL," ");
	tmp = strtok(NULL," ");
	
	strcat(truncated_dnsmsg_out,tmp);

//	load TXT signature (cert verify)
    dp->CertVerifyEntry.signature_algorithms = strtoul(tmp, NULL, 0);
	strtok(NULL," ");
	tmp = strtok(NULL," ");
	int i =0;
	while(i < 100){
		strcat(txt_record_signature, tmp);//value (1)
		tmp = strtok(NULL," ");
		if(tmp == NULL) break;
		strcat(txt_record_signature, newline);
		
		strcat(txt_record_signature, tmp);//value (2)
		tmp = strtok(NULL," ");
		if(tmp == NULL) break;
		strcat(txt_record_signature, newline);
		
		strcat(txt_record_signature, tmp);//value (3)
		strtok(NULL," ");
		tmp = strtok(NULL," ");
		if(tmp == NULL) break;
		strcat(txt_record_signature, newline);
		
		i++;
	}
	if (100 <= i ) {
		printf("SIGNATURE ERROR\n");
	}
	strcpy((char*)dp->CertVerifyEntry.cert_verify, txt_record_signature);
    return 0;
}

static SSL_CTX *create_context(){
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if(!ctx) error_handling("fail to create ssl context");
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    return ctx;
}

static void keylog_callback(const SSL* ssl, const char *line){
	FILE  * fp;
    fp = fopen("./key_log.log", "a");
    if (fp == NULL)
    {
        printf("Failed to create log file\n");
    }
    fprintf(fp, "%s\n", line);
    fclose(fp);
}

static size_t resolve_hostname(const char *host, const char *port, struct sockaddr_storage *addr){
    struct addrinfo hint;
	memset(&hint, 0, sizeof(struct addrinfo));
	hint.ai_family = AF_INET;
	hint.ai_socktype = SOCK_STREAM;
    hint.ai_protocol = IPPROTO_TCP;
	struct addrinfo *res = 0;
    if(getaddrinfo(host, port, &hint, &res) != 0)
        error_handling("fail to transform address");
    size_t len = res->ai_addrlen;
    memcpy(addr, res->ai_addr, len);
    freeaddrinfo(res);
    return len;
}
static void configure_connection(SSL *ssl){
    SSL_set_tlsext_host_name(ssl, "izone.ns-secure-dns.snu.ac.kr");
    SSL_set_connect_state(ssl);
    if(SSL_connect(ssl) <= 0){
        ERR_print_errors_fp(stderr);
        error_handling("fail to do handshake");
    }
}
static void error_handling(char *message){
    fputs(message, stderr);
    fputc('\n', stderr);
    exit(1);
}

static int dns_info_add_cb(SSL *s, unsigned int ext_type,
                            unsigned int context,
                            const unsigned char **out,
                            size_t *outlen, X509 *x, size_t chainidx,
                            int *al, void *arg)
                            {

    if (context == SSL_EXT_CLIENT_HELLO) {
        *out = (unsigned char*)malloc(sizeof(char*)*4);
        memcpy((void*)*out, &(&dns_info)->DNSCacheInfo.dns_cache_id, 4);
        *outlen = 4;
    }

    return 1;
}

static void dns_info_free_cb(SSL *s, unsigned int ext_type,
                     unsigned int context,
                     const unsigned char *out,
                     void *add_arg){
    OPENSSL_free((unsigned char *)out);
}

static int ext_parse_cb(SSL *s, unsigned int ext_type,
                        const unsigned char *in,
                        size_t inlen, int *al, void *parse_arg)
                        {
    return 1;
}

static time_t is_datetime(const char *datetime){
    // datetime format is YYYYMMDDHHMMSSz
    struct tm   time_val;

    strptime(datetime, "%Y%m%d%H%M%Sz", &time_val);

    return mktime(&time_val);       // Invalid
}


unsigned char * hex_to_base64(unsigned char *hex0, int size, unsigned char hex[])
{
	char temp[10];
	unsigned char * temc;
	unsigned char n;
	temc = hex0;
	for(int i=0; i<size ; i++) {
		sprintf(temp,"%02X",*temc );
		strcat(hex,temp);
		temc++;
	}
	unsigned char *hex_string = hex;

    static const char base64[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    size_t input_len = size;
    size_t output_len = 1500;
    char * out_buf = malloc(output_len);
    if (!out_buf) {
        return out_buf;
    }

    unsigned int digits;
    int d_len;
    char *out = out_buf;
    while (*hex_string) {
        if (sscanf(hex_string, "%3x%n", &digits, &d_len) != 1) {
            /* parse error */
            free(out_buf);
            return NULL;
        }
        switch (d_len) {
        case 3:
            *out++ = base64[digits >> 6];
            *out++ = base64[digits & 0x3f];
            break;
        case 2:
            digits <<= 4;
            *out++ = base64[digits >> 6];
            *out++ = base64[digits & 0x3f];
            *out++ = '=';
            break;
        case 1:
            *out++ = base64[digits];
            *out++ = '=';
            *out++ = '=';
        }
        hex_string += d_len;
    }

    *out++ = '\0';
    return out_buf;
}


