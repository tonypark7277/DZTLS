// echo_client_getdns.c (쿠키 프리부트 A로, A/AAAA도 EDNS COOKIE 사용, TXT 파싱 수정본)

#include "echo_client.h"

#include <arpa/nameser.h>
#include <netinet/in.h>
#include <resolv.h>
#include <string.h>
#include <pthread.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <ctype.h>

////////////////////////////////////////////////////////////////////////////////////////
//                            added for setting TCP FASTOPEN                          //
////////////////////////////////////////////////////////////////////////////////////////
#include <netinet/tcp.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include <getdns/getdns.h>
#include <getdns/getdns_extra.h>

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

const static char *DNS_RESOLVER = "43.201.156.204";

// ===== 전방 선언 =====
static void init_openssl();
int is_start;
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

static BIO *create_socket_bio(char *argv[], struct DNS_info *dp, int * is_start, int * parsing_done);
static void init_tcp_sync(char *argv[], struct DNS_info* dp, struct sockaddr_storage * addr, int sock, int * is_start, int * parsing_done);

static void tlsa_query_getdns(const char *server_ip, char *hostname,
                              unsigned char **tlsa_record_all, size_t *tlsa_len);

static unsigned char * hex_to_base64(unsigned char *bin, int size, unsigned char hex[]);

// ===== 유틸 =====
static void print_hex(const char *label, const uint8_t *p, size_t n) {
    fprintf(stderr, "%s (%zuB): ", label, n);
    for (size_t i = 0; i < n; i++) fprintf(stderr, "%02x", p[i]);
    fputc('\n', stderr);
}

static int is_ip_literal(const char *s) {
    struct in_addr v4; struct in6_addr v6;
    if (inet_pton(AF_INET, s, &v4) == 1) return 1;
    if (inet_pton(AF_INET6, s, &v6) == 1) return 1;
    return 0;
}

// ===== 스레드 인자 =====
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
    unsigned char ** tlsa_record_all;
    size_t * tlsa_len;
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
    tlsa_query_getdns(DNS_RESOLVER, args->argv[1], args->tlsa_record_all, args->tlsa_len);
    pthread_exit(NULL);
}

// ===== 전역 쿠키 캐시 =====
static uint8_t g_client_cookie[8];
static int     g_client_cookie_inited = 0;

static uint8_t g_server_cookie[32];
static size_t  g_server_cookie_len = 0;
static pthread_mutex_t g_cookie_mu = PTHREAD_MUTEX_INITIALIZER;

static void rand8(uint8_t b[8]) {
    FILE *f = fopen("/dev/urandom","rb");
    if (f) { fread(b,1,8,f); fclose(f); return; }
    for (int i=0;i<8;i++) b[i] = rand() & 0xff;
}

// 안전한 set/get
static void server_cookie_set(const uint8_t *p, size_t n) {
    if (!p) return;
    if (n > 32) n = 32;                // RFC 권고: 8–32B
    pthread_mutex_lock(&g_cookie_mu);
    memcpy(g_server_cookie, p, n);
    g_server_cookie_len = n;
    pthread_mutex_unlock(&g_cookie_mu);
}

static size_t server_cookie_get(uint8_t *out, size_t cap) {
    pthread_mutex_lock(&g_cookie_mu);
    size_t n = g_server_cookie_len;
    if (n > cap) n = cap;
    memcpy(out, g_server_cookie, n);
    pthread_mutex_unlock(&g_cookie_mu);
    return n;
}

// EDNS COOKIE 확장(add_opt_parameters) 구성 (스택 버퍼 사용)
static getdns_return_t make_cookie_ext(getdns_dict **ext_out,
                                       const uint8_t client_cookie[8],
                                       const uint8_t *server_cookie, size_t slen)
{
    if (slen > 32) slen = 32;

    getdns_dict *ext = getdns_dict_create();
    getdns_dict *optparams = getdns_dict_create();
    getdns_list *opts = getdns_list_create();
    getdns_dict *one = getdns_dict_create();
    if (!ext || !optparams || !opts || !one) return GETDNS_RETURN_GENERIC_ERROR;

    getdns_return_t r;
    if ((r = getdns_dict_set_int(one, "option_code", 10)) != GETDNS_RETURN_GOOD) return r;

    uint8_t buf[8+32];
    memcpy(buf, client_cookie, 8);
    if (server_cookie && slen) memcpy(buf+8, server_cookie, slen);
    getdns_bindata od = { (size_t)(8+slen), buf };

    if ((r = getdns_dict_set_bindata(one, "option_data", &od)) != GETDNS_RETURN_GOOD) return r;
    if ((r = getdns_list_set_dict(opts, 0, one)) != GETDNS_RETURN_GOOD) return r;
    if ((r = getdns_dict_set_list(optparams, "options", opts)) != GETDNS_RETURN_GOOD) return r;
    if ((r = getdns_dict_set_dict(ext, "add_opt_parameters", optparams)) != GETDNS_RETURN_GOOD) return r;

    *ext_out = ext; // caller destroys via getdns_dict_destroy
    return GETDNS_RETURN_GOOD;
}

// 응답에서 server-cookie 뽑기
static int extract_server_cookie(getdns_dict *resp, uint8_t *out, size_t *outlen)
{
    getdns_list *replies=NULL; if (getdns_dict_get_list(resp,"replies_tree",&replies)!=GETDNS_RETURN_GOOD) return 0;
    getdns_dict *rep0=NULL; getdns_list_get_dict(replies,0,&rep0);
    getdns_list *additional=NULL; if (!rep0 || getdns_dict_get_list(rep0,"additional",&additional)!=GETDNS_RETURN_GOOD) return 0;
    size_t n=0; getdns_list_get_length(additional,&n);
    for(size_t i=0;i<n;i++){
        getdns_dict *rr=NULL; getdns_list_get_dict(additional,i,&rr);
        uint32_t type=0; if (getdns_dict_get_int(rr,"type",&type)!=GETDNS_RETURN_GOOD || type!=41) continue; // OPT
        getdns_dict *rdata=NULL; if (getdns_dict_get_dict(rr,"rdata",&rdata)!=GETDNS_RETURN_GOOD) continue;
        getdns_list *options=NULL; if (getdns_dict_get_list(rdata,"options",&options)!=GETDNS_RETURN_GOOD) continue;
        size_t m=0; getdns_list_get_length(options,&m);
        for(size_t j=0;j<m;j++){
            getdns_dict *opt=NULL; getdns_list_get_dict(options,j,&opt);
            uint32_t code=0; if (getdns_dict_get_int(opt,"option_code",&code)!=GETDNS_RETURN_GOOD || code!=10) continue;
            getdns_bindata *bd=NULL; if (getdns_dict_get_bindata(opt, "option_data", &bd)!=GETDNS_RETURN_GOOD) continue;
            if (bd && bd->data && bd->size >= 8){
                size_t slen = bd->size - 8;
                if (slen > *outlen) slen = *outlen;
                memcpy(out, bd->data+8, slen);
                *outlen = slen;
                return 1;
            }
        }
    }
    return 0;
}

// getdns 컨텍스트 생성 + 지정 서버로 STUB 질의 (server_ip:53)
static getdns_context* make_ctx_to_server(const char *server_ip)
{
    getdns_context *ctx=NULL;
    if (getdns_context_create(&ctx, 1) != GETDNS_RETURN_GOOD) return NULL;
    getdns_context_set_resolution_type(ctx, GETDNS_RESOLUTION_STUB);

    // 네임스페이스를 DNS로만
    getdns_namespace_t nss[1] = { GETDNS_NAMESPACE_DNS };
    getdns_context_set_namespaces(ctx, 1, nss);

    // fprintf(stderr, "[DNS] Using upstream: %s:53 (stub mode)\n", server_ip);
    getdns_list *ups = getdns_list_create();
    getdns_dict *sv = getdns_dict_create();
    uint8_t ipb[4]; if (inet_pton(AF_INET, server_ip, ipb)!=1) return NULL;
    getdns_bindata ad = { 4, ipb };
    getdns_dict_set_bindata(sv, "address_data", &ad);
    getdns_dict_set_int(sv, "port", 53);
    getdns_list_set_dict(ups, 0, sv);
    getdns_context_set_upstream_recursive_servers(ctx, ups);
    return ctx;
}

// ===== 부팅(프리플라이트): 맨 처음 한 번만 서버 쿠키 확보 (기본: A 레코드 이름으로) =====
static void ensure_cookie_bootstrap(getdns_context *ctx, const char *qname, uint16_t qtype)
{
    static int bootstrapped = 0;
    if (bootstrapped) return;

    if (!g_client_cookie_inited) {
        rand8(g_client_cookie);
        g_client_cookie_inited = 1;
        // print_hex("[DNS] client-cookie", g_client_cookie, 8);
    }

    // 클라쿠키만 넣어서 BADCOOKIE 유도
    getdns_dict *ext=NULL; make_cookie_ext(&ext, g_client_cookie, NULL, 0);
    getdns_dict *resp=NULL;
    getdns_general_sync(ctx, qname, qtype, ext, &resp);
    getdns_dict_destroy(ext);

    // 서버 쿠키 추출
    if (resp) {
        uint8_t sc[64]; size_t sl=sizeof(sc);
        if (extract_server_cookie(resp, sc, &sl) && sl>0) {
            if (sl>32) sl=32;
            server_cookie_set(sc, sl);
            // print_hex("[DNS] 2 server-cookie (received)", sc, sl);
			is_start = 1;
        }
        getdns_dict_destroy(resp);
    }
    bootstrapped = 1;
}

// ===== 쿠키 포함 일반 질의 (BADCOOKIE 시 1회 갱신 재시도) =====
static getdns_return_t query_with_cookie(getdns_context *ctx,
                                         const char *qname, uint16_t qtype,
                                         getdns_dict **out_resp)
{
    if (!g_client_cookie_inited) {
        rand8(g_client_cookie);
        g_client_cookie_inited = 1;
        // print_hex("[DNS] client-cookie", g_client_cookie, 8);
    }

    uint8_t sc[32]; size_t sl = server_cookie_get(sc, sizeof(sc));
    getdns_dict *ext=NULL; make_cookie_ext(&ext, g_client_cookie, (sl?sc:NULL), sl);
    getdns_return_t r = getdns_general_sync(ctx, qname, qtype, ext, out_resp);
    getdns_dict_destroy(ext);

    // BADCOOKIE 체크
    uint32_t rcode=0, xrcode=0, status=0, full=0;
    getdns_list *replies=NULL; getdns_dict *rep0=NULL; getdns_dict *hdr=NULL;
    if (*out_resp) {
        getdns_dict_get_list(*out_resp,"replies_tree",&replies);
        getdns_list_get_dict(replies,0,&rep0);
        if (rep0 && getdns_dict_get_dict(rep0,"header",&hdr)==GETDNS_RETURN_GOOD) {
            getdns_dict_get_int(hdr,"rcode",&rcode);
            getdns_dict_get_int(hdr,"extended_rcode",&xrcode);
        }
        getdns_dict_get_int(*out_resp,"status",&status);
        full = (xrcode<<4) | (rcode&0xF);
    }

    if (full == 23) { // BADCOOKIE
        uint8_t tmp[64]; size_t tl=sizeof(tmp);
        if (extract_server_cookie(*out_resp, tmp, &tl) && tl>0) {
            if (tl>32) tl=32;
            server_cookie_set(tmp, tl);
            // print_hex("[DNS] server-cookie (received)", tmp, tl);
        }
        getdns_dict_destroy(*out_resp); *out_resp=NULL;
        sl = server_cookie_get(sc, sizeof(sc));
        ext=NULL; make_cookie_ext(&ext, g_client_cookie, (sl?sc:NULL), sl);
        r = getdns_general_sync(ctx, qname, qtype, ext, out_resp);
        getdns_dict_destroy(ext);
    }
    return r;
}

// ===== address API (+쿠키, BADCOOKIE 1회 재시도) =====
static getdns_return_t address_with_cookie(getdns_context *ctx,
                                           const char *host,
                                           getdns_dict **out_resp)
{
    if (!g_client_cookie_inited) {
        rand8(g_client_cookie);
        g_client_cookie_inited = 1;
        // print_hex("[DNS] client-cookie", g_client_cookie, 8);
    }

    uint8_t sc[32]; size_t sl = server_cookie_get(sc, sizeof(sc));
    getdns_dict *ext=NULL; make_cookie_ext(&ext, g_client_cookie, (sl?sc:NULL), sl);
    getdns_return_t r = getdns_address_sync(ctx, host, ext, out_resp);
    getdns_dict_destroy(ext);

    if (r != GETDNS_RETURN_GOOD || !*out_resp) {
        fprintf(stderr, "[DNS] address_sync r=%d, resp=%p\n", r, (void*)*out_resp);
        return r;
    }

    uint32_t rcode=0, xrcode=0, full=0, status=0;
    getdns_list *replies=NULL; getdns_dict *rep0=NULL; getdns_dict *hdr=NULL;
    getdns_dict_get_list(*out_resp,"replies_tree",&replies);
    getdns_list_get_dict(replies,0,&rep0);
    if (rep0 && getdns_dict_get_dict(rep0,"header",&hdr)==GETDNS_RETURN_GOOD) {
        getdns_dict_get_int(hdr,"rcode",&rcode);
        getdns_dict_get_int(hdr,"extended_rcode",&xrcode);
    }
    getdns_dict_get_int(*out_resp,"status",&status);
    full = (xrcode<<4) | (rcode&0xF);
    // fprintf(stderr, "[DNS] address rcode=%u ext=%u full=%u status=%u\n",
            // rcode, xrcode, full, status);

    if (full == 23) { // BADCOOKIE
        uint8_t tmp[64]; size_t tl=sizeof(tmp);
        if (extract_server_cookie(*out_resp, tmp, &tl) && tl>0) {
            if (tl>32) tl=32;
            server_cookie_set(tmp, tl);
            // print_hex("[DNS] server-cookie (received)", tmp, tl);
        }
        getdns_dict_destroy(*out_resp); *out_resp=NULL;

        sl = server_cookie_get(sc, sizeof(sc));
        ext=NULL; make_cookie_ext(&ext, g_client_cookie, (sl?sc:NULL), sl);
        r = getdns_address_sync(ctx, host, ext, out_resp);
        getdns_dict_destroy(ext);
        // fprintf(stderr, "[DNS] address retry r=%d\n", r);
    }
    return r;
}

// address 응답 파싱 → sockaddr_storage 배열 채우기
static int resolve_with_cookie_addrs(getdns_context *ctx,
                                     const char *host,
                                     struct sockaddr_storage *out, size_t max_out,
                                     size_t *out_count)
{
    *out_count = 0;

    getdns_dict *resp=NULL;
    getdns_return_t r = address_with_cookie(ctx, host, &resp);
    if (r != GETDNS_RETURN_GOOD || !resp) return -1;

    // ① just_address_answers 이용
    getdns_list *alist=NULL;
    if (getdns_dict_get_list(resp, "just_address_answers", &alist) == GETDNS_RETURN_GOOD) {
        size_t n=0; getdns_list_get_length(alist, &n);
        for (size_t i=0; i<n && *out_count < max_out; i++) {
            getdns_dict *a=NULL; getdns_list_get_dict(alist, i, &a);
            if (!a) continue;
            getdns_bindata *ad=NULL, *atype=NULL;
            if (getdns_dict_get_bindata(a, "address_data", &ad) != GETDNS_RETURN_GOOD || !ad) continue;
            if (getdns_dict_get_bindata(a, "address_type", &atype) != GETDNS_RETURN_GOOD || !atype) continue;

            if (ad->size==4 && atype->size==4 && memcmp(atype->data,"IPv4",4)==0) {
                struct sockaddr_in *sin = (struct sockaddr_in*)&out[*out_count];
                memset(sin,0,sizeof(*sin)); sin->sin_family=AF_INET;
                memcpy(&sin->sin_addr, ad->data, 4);
                (*out_count)++;
            } else if (ad->size==16 && atype->size==4 && memcmp(atype->data,"IPv6",4)==0) {
                struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)&out[*out_count];
                memset(sin6,0,sizeof(*sin6)); sin6->sin6_family=AF_INET6;
                memcpy(&sin6->sin6_addr, ad->data, 16);
                (*out_count)++;
            }
        }
    }

    // ② 필요시 replies_tree에서 A/AAAA 직접 파싱
    if (*out_count == 0) {
        getdns_list *replies=NULL; getdns_dict *rep0=NULL; getdns_list *answer=NULL;
        if (getdns_dict_get_list(resp,"replies_tree",&replies)==GETDNS_RETURN_GOOD &&
            getdns_list_get_dict(replies,0,&rep0)==GETDNS_RETURN_GOOD &&
            getdns_dict_get_list(rep0,"answer",&answer)==GETDNS_RETURN_GOOD) {

            size_t an=0; getdns_list_get_length(answer,&an);
            for (size_t i=0; i<an && *out_count<max_out; i++) {
                getdns_dict *rr=NULL; getdns_list_get_dict(answer,i,&rr);
                uint32_t type=0; getdns_dict_get_int(rr,"type",&type);
                if (type!=1 && type!=28) continue;
                getdns_dict *rdata=NULL; if (getdns_dict_get_dict(rr,"rdata",&rdata)!=GETDNS_RETURN_GOOD) continue;

                if (type==1) { // A
                    getdns_bindata *v4=NULL;
                    if (getdns_dict_get_bindata(rdata,"ipv4_address",&v4)==GETDNS_RETURN_GOOD &&
                        v4 && v4->data && v4->size==4) {
                        struct sockaddr_in *sin = (struct sockaddr_in*)&out[*out_count];
                        memset(sin,0,sizeof(*sin)); sin->sin_family=AF_INET;
                        memcpy(&sin->sin_addr, v4->data, 4);
                        (*out_count)++;
                    }
                } else { // AAAA
                    getdns_bindata *v6=NULL;
                    if (getdns_dict_get_bindata(rdata,"ipv6_address",&v6)==GETDNS_RETURN_GOOD &&
                        v6 && v6->data && v6->size==16) {
                        struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)&out[*out_count];
                        memset(sin6,0,sizeof(*sin6)); sin6->sin6_family=AF_INET6;
                        memcpy(&sin6->sin6_addr, v6->data, 16);
                        (*out_count)++;
                    }
                }
            }
        }
    }

    getdns_dict_destroy(resp);
    return (*out_count > 0) ? 0 : -1;
}

int main(int argc, char *argv[]){
    res_init();
    init_openssl();
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL) {
        error_handling("Failed to create the SSL_CTX\n");
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_load_verify_locations(ctx, "./dns/cert/CarolCert.pem", "./dns/cert/");
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_keylog_callback(ctx, keylog_callback);
    SSL_CTX_set_default_verify_paths(ctx);
    SSL * ssl = NULL;
    BIO * bio = NULL;

    if(argc != 3){
        printf("Usage : %s <host> <port>\n", argv[0]);
        exit(1);
    }
    if (is_ip_literal(argv[1])) {
        fprintf(stderr, "[WARN] Host is IP literal. TLSA requires FQDN; TLSA will be skipped.\n");
    }

    int sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(sock < 0){
        error_handling("socket() error");
    }

    char * ztls_cert;
    struct sockaddr_storage addr;
    char txt_record_except_signature[BUF_SIZE];
    char *txt_record_all = NULL;
    unsigned char *tlsa_record_all = NULL;
    size_t tlsa_len = 0;
    char hex_out_cert[8192] = "";
    unsigned char hex_buffer[8192] = "";

    is_start = -1;
    int parsing_done = -1;

    // log
    printf("****start****\n");
    if (!DNS) {
        struct timespec begin;
        clock_gettime(CLOCK_MONOTONIC, &begin);
        printf("start : %f\n",(begin.tv_sec) + (begin.tv_nsec) / 1000000000.0);
    }

    if(DNS){
        _res.options = _res.options | RES_USE_EDNS0 ;  // use EDNS0 

		struct timespec begin;
		clock_gettime(CLOCK_MONOTONIC, &begin);
		printf("start : %f\n",(begin.tv_sec) + (begin.tv_nsec) / 1000000000.0);    

        // BIO 생성 스레드
        struct arg_struct_bio args_bio;
        args_bio.argv = argv;
        args_bio.dp = &dns_info;
        args_bio.is_start = &is_start;
        args_bio.parsing_done = &parsing_done;

        pthread_t ptid_bio;
        pthread_create(&ptid_bio, NULL, &thread_create_socket_bio, (void *) &args_bio);

        // TLSA 스레드
        struct arg_struct2 args2;
        args2.argv = argv;
        args2.tlsa_record_all = &tlsa_record_all;
        args2.tlsa_len = &tlsa_len;
        args2.is_start = &is_start;

        pthread_t ptid_tlsa;
        pthread_create(&ptid_tlsa, NULL, &thread_tlsa_query, (void *) &args2);        
                   
        // ===== TXT =====
		while(is_start < 0) { /* wait */ }
        clock_gettime(CLOCK_MONOTONIC, &begin);
        printf("start DNS TXT query: %f\n",(begin.tv_sec) + (begin.tv_nsec) / 1000000000.0);

        getdns_context *gctx = make_ctx_to_server(DNS_RESOLVER);
        if (!gctx) error_handling("getdns ctx fail");
        // TXT 쿼리 (쿠키 재사용) — 프리부트는 create_socket_bio()에서 A로 이미 수행됨
		
        getdns_dict *resp=NULL;
		getdns_return_t r = query_with_cookie(gctx, argv[1], GETDNS_RRTYPE_TXT, &resp);
		if (r != GETDNS_RETURN_GOOD || !resp) {
			fprintf(stderr, "[DNS] TXT query failed (getdns r=%d). Continue without TXT.\n", r);
		} else {
			// 상태/개수 디버그
			getdns_list *replies=NULL; getdns_dict *rep0=NULL; getdns_dict *hdr=NULL;
			uint32_t rcode=0, xrcode=0, status=0;
			getdns_dict_get_list(resp,"replies_tree",&replies);
			getdns_list_get_dict(replies,0,&rep0);
			if (rep0 && getdns_dict_get_dict(rep0,"header",&hdr)==GETDNS_RETURN_GOOD) {
				getdns_dict_get_int(hdr,"rcode",&rcode);
				getdns_dict_get_int(hdr,"extended_rcode",&xrcode);
			}
			getdns_dict_get_int(resp,"status",&status);
			getdns_list *answer=NULL; getdns_dict_get_list(rep0,"answer",&answer);
			size_t an_len=0; getdns_list_get_length(answer,&an_len);
			// fprintf(stderr, "[DNS] TXT rcode=%u ext=%u answers=%zu status=%u\n",
			// 		rcode, xrcode, an_len, status);

			// TXT 파싱(여러 RR/여러 chunk 지원)
			if (an_len == 0) {
				fprintf(stderr, "[DNS] No TXT RR. Continue without TXT.\n");
			} else {
				// 모든 TXT RR과 그 안의 string-chunk를 전부 이어붙임(공백/개행 구분은 필요에 맞게)
				// 최대 길이 보호: BUF_SIZE-1
				size_t wrote = 0;
				txt_record_all = (char*)malloc(BUF_SIZE);
				if (!txt_record_all) error_handling("malloc TXT");
				txt_record_all[0] = '\0';

				for (size_t i=0; i<an_len; i++) {
					getdns_dict *rr=NULL; getdns_list_get_dict(answer, i, &rr);
					uint32_t type=0; getdns_dict_get_int(rr, "type", &type);
					if (type != 16) continue; // TXT = 16

					getdns_dict *rdata=NULL; if (getdns_dict_get_dict(rr,"rdata",&rdata)!=GETDNS_RETURN_GOOD) continue;
					getdns_list *txts = NULL;
					if (getdns_dict_get_list(rdata, "txt_strings", &txts) != GETDNS_RETURN_GOOD) {
						fprintf(stderr, "[DNS] TXT rdata has no 'txt_strings' list\n");
						txts = NULL;
					}
					size_t tlen = 0;
					if (txts) getdns_list_get_length(txts, &tlen);

					for (size_t j=0; j<tlen; j++) {
						getdns_bindata *bd=NULL; 
						if (getdns_list_get_bindata(txts, j, &bd)==GETDNS_RETURN_GOOD && bd && bd->data && bd->size) {
							size_t tocpy = bd->size;
							if (wrote + tocpy + 1 >= BUF_SIZE) { // +1 for '\n' or '\0'
								tocpy = (BUF_SIZE-1) - wrote;
							}
							memcpy(txt_record_all + wrote, bd->data, tocpy);
							wrote += tocpy;
							if (wrote < BUF_SIZE-1) txt_record_all[wrote++] = '\n'; // 구분자(원하면 공백으로 변경)
							if (wrote >= BUF_SIZE-1) break;
						}
					}
					if (wrote >= BUF_SIZE-1) break;
				}

				if (wrote == 0) {
					// TXT가 있었지만 string 데이터가 비어있는 경우
					free(txt_record_all);
					txt_record_all = NULL;
					fprintf(stderr, "[DNS] TXT RR present but no string data. Continue without TXT.\n");
				} else {
					txt_record_all[wrote-1] = '\0'; // 마지막 구분자 정리
					// 여기서 txt_record_all을 load_dns_info2에 넘기면 됨
				}
			}

			getdns_dict_destroy(resp);
        }
        clock_gettime(CLOCK_MONOTONIC, &begin);
        printf("complete DNS TXT query : %f\n",(begin.tv_sec) + (begin.tv_nsec) / 1000000000.0);

        // TLSA 스레드 완료 대기
        pthread_join(ptid_tlsa, NULL);

        // ===== TLSA 바이트를 base64 PEM으로 변환 (실제 길이 기반) =====
        if (tlsa_record_all && tlsa_len > 0) {
            unsigned char *based64_out = NULL;
            based64_out = hex_to_base64(tlsa_record_all, (int)tlsa_len, hex_buffer);

            // 64열 개행
            size_t b64len = strlen((char*)based64_out);
            const char *nl = "\n";
            size_t pos = 0;
            while (pos + 64 <= b64len) {
                strncat(hex_out_cert, (char*)based64_out + pos, 64);
                strcat(hex_out_cert, nl);
                pos += 64;
            }
            if (pos < b64len) {
                strcat(hex_out_cert, (char*)based64_out + pos);
                strcat(hex_out_cert, nl);
            }

            char *ztls_cert = hex_out_cert;
            char *ztls_cert_orig = (char*)based64_out; // 원본 b64 (줄바꿈 전)
            char truncated_dnsmsg_out[BUF_SIZE] = {0};

            if (txt_record_all) {
                load_dns_info2(&dns_info, truncated_dnsmsg_out, txt_record_all, ztls_cert, ztls_cert_orig);
            }
            parsing_done = 1;

            SSL_CTX_add_custom_ext(ctx, 53, SSL_EXT_CLIENT_HELLO, dns_info_add_cb, dns_info_free_cb,NULL,NULL,NULL);
            if(dns_info.KeyShareEntry.group == 29){  // X25519
                SSL_CTX_set1_groups_list(ctx, "X25519");
            }
        } else {
            fprintf(stderr,"[DNS] TLSA empty; continue without it.\n");
            parsing_done = 1;
        }

        ssl = SSL_new(ctx);
        SSL_set_wfd(ssl, DNS); // fd : 1 => ZTLS, fd : 0 => TLS 1.3

        // 유효기간 체크
        if(dns_info.DNSCacheInfo.validity_period_not_before < time(NULL) &&
           dns_info.DNSCacheInfo.validity_period_not_after > time(NULL)){
            printf("Valid Period\n");
        } else {
            printf("Not Valid Period\n");
        }

        if (dns_info.KeyShareEntry.skey)
            SSL_use_PrivateKey(ssl, dns_info.KeyShareEntry.skey);
        if (dns_info.cert)
            SSL_use_certificate(ssl, dns_info.cert);

        if(dns_info.CertVerifyEntry.signature_algorithms == 2052) { // rsa-pss-rsae-sha256
            strcat(txt_record_except_signature, "\n");
            strcat((char*)dns_info.CertVerifyEntry.cert_verify, "\n");
            SSL_export_keying_material(ssl, (unsigned char*) txt_record_except_signature, 0, NULL, 0,
                                       dns_info.CertVerifyEntry.cert_verify, BUF_SIZE, 0);
        }

        pthread_join(ptid_bio, NULL);
        if (args_bio.bio == NULL)
            error_handling("thread_create_socket_bio() error!\n");
        bio = args_bio.bio;
        SSL_set_bio(ssl, bio, bio);

        // 확실한 SNI 설정
        SSL_set_tlsext_host_name(ssl, argv[1]);
    } else {
        // DNS 경로가 아니어도 소켓/BIO는 만들어야 하므로 직접 생성
        is_start = 1;
        parsing_done = 1;
        ssl = SSL_new(ctx);
        SSL_set_wfd(ssl, DNS);
        bio = create_socket_bio(argv, &dns_info, &is_start, &parsing_done);
        if (bio == NULL)
            error_handling("create_socket_bio() error!\n");
        SSL_set_bio(ssl, bio, bio);
        SSL_set_tlsext_host_name(ssl, argv[1]);
    }

    /*
     * handshake start
     */
    configure_connection(ssl); // SSL_do_handshake

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
    free(txt_record_all);
    free(tlsa_record_all);
    return 0;
}

static BIO *create_socket_bio(char *argv[], struct DNS_info *dp, int * is_start, int * parsing_done){
    // 이 함수가 쿠키 프리부트를 직접 수행하므로 대기 불필요   

    BIO *bio = NULL;
    int sock = -1;

    struct timespec begin1, begin2;
    clock_gettime(CLOCK_MONOTONIC, &begin1);
    printf("start A and AAAA DNS records query : %f\n",(begin1.tv_sec) + (begin1.tv_nsec) / 1000000000.0);

    // getdns 컨텍스트 + A로 프리부트
    getdns_context *gctx = make_ctx_to_server(DNS_RESOLVER);
    if (!gctx) error_handling("getdns ctx fail");
    // ★ 기본 프리부트: A 레코드로 EDNS COOKIE 확보
    ensure_cookie_bootstrap(gctx, argv[1], GETDNS_RRTYPE_A);
	is_start = 1; //user trigger 
    // 필요시 IPv6 대비
    // ensure_cookie_bootstrap(gctx, argv[1], GETDNS_RRTYPE_AAAA);

    // 쿠키 포함 주소 해석
    struct sockaddr_storage addrs[16];
    size_t addrc = 0;
    if (resolve_with_cookie_addrs(gctx, argv[1], addrs, 16, &addrc) != 0 || addrc == 0) {
        error_handling("cookie A/AAAA resolve failed");
    }

    // 포트 설정
    int port = atoi(argv[2]);
    for (size_t i=0;i<addrc;i++) {
        if (addrs[i].ss_family == AF_INET) {
            ((struct sockaddr_in*)&addrs[i])->sin_port = htons(port);
        } else if (addrs[i].ss_family == AF_INET6) {
            ((struct sockaddr_in6*)&addrs[i])->sin6_port = htons(port);
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &begin2);
    printf("complete A and AAAA DNS records query : %f\n",(begin2.tv_sec) + (begin2.tv_nsec) / 1000000000.0);

    // connect 시도
    for (size_t i=0; i<addrc; i++) {
        sock = BIO_socket(addrs[i].ss_family, SOCK_STREAM, 0, 0);
        if (sock == -1) continue;

        if (TFO) {
            if (DNS) {
                while (*parsing_done < 0) { /* wait */ }
                // uint64_t temp = 0xaa5fd10d;
				uint64_t k0 = 0;
				uint64_t k1 = 0;
				for (size_t j = 0; j < 8; j++) {
					k0 += g_client_cookie[j] << (8*(7-j));
					k1 += g_server_cookie[j+8] << (8*(7-j));
				}
                dp->PreCookie.pre_cookie[0] = k0;
				dp->PreCookie.pre_cookie[1] = k1;
                if (setsockopt(sock, SOL_TCP, TCP_FASTOPEN_KEY, dp->PreCookie.pre_cookie, sizeof(dp->PreCookie.pre_cookie)) < 0) {
                    error_handling("Setting tcp_fastopen_key failed");
                }
            }
            int opt = 1;
            if (setsockopt(sock, IPPROTO_TCP, TCP_FASTOPEN_CONNECT, &opt, sizeof(opt)) < 0) {
                error_handling("setsockopt() error!");
            }
        }

        if (!BIO_connect(sock, (const BIO_ADDR *)&addrs[i], BIO_SOCK_NODELAY)) {
            BIO_closesocket(sock);
            sock = -1;
            continue;
        }
        break; // 성공
    }

    getdns_context_destroy(gctx);

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
    while(is_start < 0) { /* wait */ }

    struct timespec begin1, begin2;
    clock_gettime(CLOCK_MONOTONIC, &begin1);
    printf("start A and AAAA DNS records query : %f\n",(begin1.tv_sec) + (begin1.tv_nsec) / 1000000000.0);
    size_t len = resolve_hostname(argv[1], argv[2], addr);
    clock_gettime(CLOCK_MONOTONIC, &begin2);
    printf("complete A and AAAA DNS records query : %f\n",(begin2.tv_sec) + (begin2.tv_nsec) / 1000000000.0);

    if (TFO) {
        if (DNS) {
            while(*parsing_done < 0) { /* wait */ }
            uint64_t temp = 0xaa5fd10d;
            dp->PreCookie.pre_cookie[0] += temp << 32;
            setsockopt(sock, SOL_TCP, TCP_FASTOPEN_KEY, dp->PreCookie.pre_cookie, sizeof(dp->PreCookie.pre_cookie));
        }
        int opt = 1;
        if (setsockopt(sock, IPPROTO_TCP, TCP_FASTOPEN_CONNECT, &opt, sizeof(opt)) < 0) {
            error_handling("setsockopt() error!");
        }
    }

    if(connect(sock, (struct sockaddr*) addr, len) < 0){
        error_handling("connect() error!");
    }else{
        clock_gettime(CLOCK_MONOTONIC, &begin2);
        printf("complete TCP Sync : %f\n",(begin2.tv_sec) + (begin2.tv_nsec) / 1000000000.0);
    }
}

// ===== TLSA(getdns) – 443 고정, 쿠키 재사용 =====
static void tlsa_query_getdns(const char *server_ip, char *hostname,
                              unsigned char **tlsa_record_all, size_t *tlsa_len)
{
    
	while(is_start < 0) { /* wait */ }
	
    char qname[256]; snprintf(qname,sizeof(qname), "_443._tcp.%s", hostname);
    // fprintf(stderr, "[DNS] TLSA QNAME: %s\n", qname);

    getdns_context *ctx = make_ctx_to_server(server_ip);
    if (!ctx) error_handling("getdns ctx fail");

    // (중복 프리부트는 불필요) — A에서 이미 프리부트됨

    getdns_dict *resp = NULL;
    getdns_return_t r = query_with_cookie(ctx, qname, GETDNS_RRTYPE_TLSA, &resp);
    if (r != GETDNS_RETURN_GOOD || !resp) {
        fprintf(stderr, "no TLSA answer\n");
        getdns_context_destroy(ctx);
        return;
    }

    // answer 파싱
    getdns_list *replies=NULL; getdns_dict *rep0=NULL;
    getdns_dict_get_list(resp,"replies_tree",&replies); getdns_list_get_dict(replies,0,&rep0);
    getdns_list *answer=NULL; getdns_dict_get_list(rep0,"answer",&answer);
    size_t an_len=0; getdns_list_get_length(answer,&an_len);
    if (an_len==0) {
        fprintf(stderr, "no TLSA answer\n");
        getdns_dict_destroy(resp);
        getdns_context_destroy(ctx);
        return;
    }

    getdns_dict *rr=NULL; getdns_list_get_dict(answer,0,&rr);
    getdns_dict *rdata=NULL; getdns_dict_get_dict(rr,"rdata",&rdata);
    // certificate_association_data
    getdns_bindata *ad=NULL;
    if (getdns_dict_get_bindata(rdata,"certificate_association_data",&ad) == GETDNS_RETURN_GOOD
        && ad && ad->data && ad->size) {
        *tlsa_record_all = (unsigned char*)malloc(ad->size);
        memcpy(*tlsa_record_all, ad->data, ad->size);
        *tlsa_len = ad->size;
    } else {
        fprintf(stderr, "TLSA parse error: no association_data\n");
    }

    getdns_dict_destroy(resp);
    getdns_context_destroy(ctx);
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
    char txt_record_signature[BUF_SIZE] = {0};
    char newline[4] = "\n";
    char pre_cookie_tok[20] = "";
    char * ztls_version = (char*)"v=ztls1";

    // v=ztls1 check
    tmp = strtok(dnsmsg," ");
    strcat(truncated_dnsmsg_out,tmp);
    strtok(NULL, " ");
    if(0!=strcmp(tmp,ztls_version)){
        printf("DNS TXT record's ZTLS version error\n");
    }

    // load dns cache info
    tmp = strtok(NULL," ");
    strcat(truncated_dnsmsg_out,tmp);
    dp->DNSCacheInfo.validity_period_not_before = is_datetime(tmp);
    printf("DNS cache period: %s~~", tmp);
    strtok(NULL," ");
    tmp = strtok(NULL," ");
    strcat(truncated_dnsmsg_out,tmp);
    dp->DNSCacheInfo.validity_period_not_after = is_datetime(tmp);
    printf("%s\n", tmp);
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
    char * begin_cert = (char*)"B_CERTIFICATE";
    char * end_cert = (char*)"E_CERTIFICATE";

    strcat(truncated_dnsmsg_out,begin_cert);
    strcat(truncated_dnsmsg_out,ztls_cert_orig);
    strcat(truncated_dnsmsg_out,end_cert);
    strcat(certificate_prefix2, ztls_cert);
    strcat(certificate_prefix2, certificate_postfix2);

    bio_cert = BIO_new(BIO_s_mem());
    BIO_puts(bio_cert, certificate_prefix2);
    PEM_read_bio_X509(bio_cert, &(dp->cert), NULL, NULL);

    // Client Certificate Request
    strtok(NULL," ");
    tmp = strtok(NULL," ");
    strcat(truncated_dnsmsg_out,tmp);
    printf("Client Certificate Request: %s\n", tmp);

    // AZTLS pre-cookie for tcp fastopen
    strtok(NULL, " ");
    tmp = strtok(NULL, " ");
    strcat(truncated_dnsmsg_out, tmp);
    for (int i = 0; i < 4; i++) {
        strcpy(pre_cookie_tok, "0x");
        strncat(pre_cookie_tok, tmp+16*i, 16);
        dp->PreCookie.pre_cookie[i] = strtoul(pre_cookie_tok, NULL, 16);
    }

    // Signature algorithm
    strtok(NULL," ");
    tmp = strtok(NULL," ");
    strcat(truncated_dnsmsg_out,tmp);
    dp->CertVerifyEntry.signature_algorithms = strtoul(tmp, NULL, 0);

    // TXT signature (multi line) — 그대로 라인누적
    strtok(NULL," ");
    tmp = strtok(NULL," ");
    int i =0;
    while(tmp && i < 100){
        strcat(txt_record_signature, tmp);
        strcat(txt_record_signature, newline);
        strtok(NULL, " ");
        tmp = strtok(NULL, " ");
        if(!tmp) break;
        strcat(txt_record_signature, tmp);
        strcat(txt_record_signature, newline);
        strtok(NULL, " ");
        tmp = strtok(NULL, " ");
        if(!tmp) break;
        strcat(txt_record_signature, tmp);
        strcat(txt_record_signature, newline);
        strtok(NULL, " ");
        tmp = strtok(NULL, " ");
        i++;
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
    // SNI는 main에서 argv[1]로 설정
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
        *out = (unsigned char*)malloc(4);
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
    return mktime(&time_val);
}

unsigned char * hex_to_base64(unsigned char *bin, int size, unsigned char hex[])
{
    // bin(바이너리) → 헥사 문자열 작성
    char tmp[3];
    for (int i=0;i<size;i++){
        sprintf(tmp, "%02X", bin[i]);
        strcat((char*)hex, tmp);
    }
    unsigned char *hex_string = hex;

    static const char base64[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    size_t input_len = strlen((char*)hex_string);
    size_t output_len = input_len + input_len/2 + 8;
    char * out_buf = malloc(output_len);
    if (!out_buf) return NULL;

    unsigned int digits;
    int d_len;
    char *out = out_buf;
    while (*hex_string) {
        if (sscanf((char*)hex_string, "%3x%n", &digits, &d_len) != 1) {
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
    return (unsigned char*)out_buf;
}
