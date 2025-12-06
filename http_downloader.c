// http_downloader.c
// Build: make
// Run:   ./http_downloader -u "https://www.tcpdump.org/release/libpcap-1.10.5.tar.xz" -n 5 -o libpcap-1.10.5.tar.xz
// Notes:
//  - Uses HTTP/1.1 over TLS (OpenSSL), SNI enabled
//  - HEAD to get Content-Length
//  - Parallel Range GETs via pthreads
//  - Writes part_1..part_n and assembles the final -o file
//  - No redirects/error handling (per assignment allowance)

#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#define USER_AGENT "http_downloader/1.0 (+student project)"
#define HDR_BUF_SZ 65536
#define IO_BUF_SZ  8192

typedef struct {
    char host[1024];
    char path[4096];
    int  port;
} url_t;

typedef struct {
    char host[1024];
    char path[4096];
    int  port;
    long long start;    // inclusive
    long long end;      // inclusive
    int index;          // 1..n for part_i
} part_job_t;

typedef struct {
    int rc;                 // 0 ok
    long long bytes_written;
} part_result_t;

typedef struct {
    part_job_t job;
    part_result_t result;
} thread_ctx_t;

// -------------------- util --------------------
static void die(const char *fmt, ...) __attribute__((noreturn));
static void die(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(EXIT_FAILURE);
}

static void warnx(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

// -------------------- url parsing --------------------
static int parse_https_url(const char *u, url_t *out) {
    memset(out, 0, sizeof(*out));
    out->port = 443;

    if (strncmp(u, "https://", 8) != 0) {
        warnx("Only https:// URLs are supported");
        return -1;
    }
    const char *p = u + 8;
    const char *slash = strchr(p, '/');
    if (!slash) {
        size_t hostlen = strlen(p);
        if (hostlen == 0 || hostlen >= sizeof(out->host)) return -1;
        memcpy(out->host, p, hostlen); out->host[hostlen] = '\0';
        strcpy(out->path, "/");
    } else {
        size_t hostlen = (size_t)(slash - p);
        if (hostlen == 0 || hostlen >= sizeof(out->host)) return -1;
        memcpy(out->host, p, hostlen); out->host[hostlen] = '\0';
        if (strlen(slash) >= sizeof(out->path)) return -1;
        strcpy(out->path, slash);
    }
    // host:port?
    char *colon = strchr(out->host, ':');
    if (colon) {
        *colon = '\0';
        int port = atoi(colon + 1);
        if (port <= 0 || port > 65535) return -1;
        out->port = port;
    }
    return 0;
}

// -------------------- net + TLS helpers --------------------
static int connect_tcp(const char *host, int port) {
    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%d", port);
    struct addrinfo hints, *res = NULL, *rp = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;

    int gai = getaddrinfo(host, portstr, &hints, &res);
    if (gai != 0) { warnx("getaddrinfo: %s", gai_strerror(gai)); return -1; }

    int fd = -1;
    for (rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

static SSL_CTX* ssl_ctx_new_client(void) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) return NULL;
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    return ctx;
}

static int ssl_write_all(SSL *ssl, const void *buf, size_t len) {
    const unsigned char *p = (const unsigned char*)buf;
    size_t off = 0;
    while (off < len) {
        int w = SSL_write(ssl, p + off, (int)(len - off));
        if (w <= 0) return -1;
        off += (size_t)w;
    }
    return 0;
}

// Read headers until \r\n\r\n. Store in hdr_out. Return prefilled body bytes in body_buf.
static ssize_t ssl_read_headers(SSL *ssl, char *hdr_out, size_t hdr_out_sz,
                                unsigned char *body_buf, size_t body_bufsz) {
    size_t hdr_len = 0, prefill = 0;
    unsigned char tmp[IO_BUF_SZ];
    const char *needle = "\r\n\r\n";

    while (1) {
        int r = SSL_read(ssl, tmp, sizeof(tmp));
        if (r <= 0) return -1;

        for (int i = 0; i < r; i++) {
            if (hdr_len + 1 < hdr_out_sz) hdr_out[hdr_len] = tmp[i];
            hdr_len++;
            if (hdr_len >= 4) {
                size_t store_len = hdr_len < hdr_out_sz ? hdr_len : hdr_out_sz - 1;
                if (hdr_len <= hdr_out_sz && store_len >= 4) {
                    if (memcmp(&hdr_out[store_len - 4], needle, 4) == 0) {
                        int remain = r - i - 1;
                        if (remain > 0 && body_buf && body_bufsz) {
                            size_t cpy = (size_t)remain > body_bufsz ? body_bufsz : (size_t)remain;
                            memcpy(body_buf, &tmp[i+1], cpy);
                            prefill = cpy;
                        }
                        if (hdr_len >= hdr_out_sz) hdr_out[hdr_out_sz - 1] = '\0';
                        else hdr_out[store_len - 4] = '\0';
                        return (ssize_t)prefill;
                    }
                }
            }
        }
        if (hdr_len > 1024*1024) return -1; // sanity cap
    }
}

static int parse_status_code(const char *headers) {
    // Expect: HTTP/1.1 200 OK
    const char *sp = strchr(headers, ' ');
    if (!sp) return -1;
    return atoi(sp + 1);
}

static long long parse_content_length_hdr(const char *headers) {
    const char *p = headers;
    while (p && *p) {
        const char *e = strstr(p, "\r\n");
        size_t len = e ? (size_t)(e - p) : strlen(p);
        if (len >= 16 && strncasecmp(p, "Content-Length:", 15) == 0) {
            const char *q = p + 15;
            while (*q == ' ' || *q == '\t') q++;
            long long v = atoll(q);
            return v > 0 ? v : -1;
        }
        if (!e) break;
        p = e + 2;
    }
    return -1;
}

// -------------------- HEAD to get total length --------------------
static long long https_head_get_length(const url_t *url) {
    long long clen = -1;
    int fd = connect_tcp(url->host, url->port);
    if (fd < 0) { warnx("connect failed"); return -1; }

    SSL_CTX *ctx = ssl_ctx_new_client();
    if (!ctx) { close(fd); return -1; }
    SSL *ssl = SSL_new(ctx);
    if (!ssl) { SSL_CTX_free(ctx); close(fd); return -1; }
    SSL_set_tlsext_host_name(ssl, url->host);
    SSL_set_fd(ssl, fd);
    if (SSL_connect(ssl) != 1) { warnx("SSL_connect failed"); SSL_free(ssl); SSL_CTX_free(ctx); close(fd); return -1; }

    char req[2048];
    int n = snprintf(req, sizeof(req),
        "HEAD %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: %s\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n"
        "\r\n",
        url->path, url->host, USER_AGENT);
    if (n <= 0 || (size_t)n >= sizeof(req)) { warnx("request too large"); goto out; }
    if (ssl_write_all(ssl, req, (size_t)n) != 0) { warnx("write failed"); goto out; }

    char hdr[HDR_BUF_SZ];
    if (ssl_read_headers(ssl, hdr, sizeof(hdr), NULL, 0) < 0) { warnx("read headers failed"); goto out; }

    int code = parse_status_code(hdr);
    if (code != 200) { warnx("HEAD status %d", code); /* still try parse */ }
    clen = parse_content_length_hdr(hdr);

out:
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(fd);
    return clen;
}

// -------------------- part downloader --------------------
static void* thread_download(void *arg) {
    thread_ctx_t *ctx = (thread_ctx_t*)arg;
    part_job_t *j = &ctx->job;

    int fd = connect_tcp(j->host, j->port);
    if (fd < 0) { ctx->result.rc = 1; return NULL; }

    SSL_CTX *sctx = ssl_ctx_new_client();
    if (!sctx) { close(fd); ctx->result.rc = 2; return NULL; }
    SSL *ssl = SSL_new(sctx);
    if (!ssl) { SSL_CTX_free(sctx); close(fd); ctx->result.rc = 3; return NULL; }
    SSL_set_tlsext_host_name(ssl, j->host);
    SSL_set_fd(ssl, fd);
    if (SSL_connect(ssl) != 1) { ctx->result.rc = 4; SSL_free(ssl); SSL_CTX_free(sctx); close(fd); return NULL; }

    char req[2048];
    int n = snprintf(req, sizeof(req),
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: %s\r\n"
        "Accept: */*\r\n"
        "Range: bytes=%lld-%lld\r\n"
        "Connection: close\r\n"
        "\r\n",
        j->path, j->host, USER_AGENT, j->start, j->end);
    if (n <= 0 || (size_t)n >= sizeof(req)) { ctx->result.rc = 5; goto out_fail; }
    if (ssl_write_all(ssl, req, (size_t)n) != 0) { ctx->result.rc = 6; goto out_fail; }

    char hdr[HDR_BUF_SZ];
    unsigned char pre[IO_BUF_SZ];
    ssize_t prelen = ssl_read_headers(ssl, hdr, sizeof(hdr), pre, sizeof(pre));
    if (prelen < 0) { ctx->result.rc = 7; goto out_fail; }

    int code = parse_status_code(hdr);
    if (!(code == 206 || code == 200)) { ctx->result.rc = 8; goto out_fail; }
    if (code == 200 && j->start > 0) { // server ignored Range
        ctx->result.rc = 9; goto out_fail;
    }

    // Content-Length here is the length of THIS response body (part size)
    long long part_len = parse_content_length_hdr(hdr);
    if (part_len < 0) { // fallback: compute from range
        part_len = j->end - j->start + 1;
    }

    char partname[64];
    snprintf(partname, sizeof(partname), "part_%d", j->index);
    FILE *out = fopen(partname, "wb");
    if (!out) { ctx->result.rc = 10; goto out_fail; }

    long long written = 0;
    if (prelen > 0) {
        size_t w = fwrite(pre, 1, (size_t)prelen, out);
        written += (long long)w;
        if (w < (size_t)prelen) { fclose(out); ctx->result.rc = 11; goto out_fail; }
    }

    unsigned char buf[IO_BUF_SZ];
    while (written < part_len) {
        int r = SSL_read(ssl, buf, sizeof(buf));
        if (r <= 0) break;
        size_t w = fwrite(buf, 1, (size_t)r, out);
        written += (long long)w;
        if (w < (size_t)r) { fclose(out); ctx->result.rc = 12; goto out_fail; }
    }
    fclose(out);
    ctx->result.bytes_written = written;
    ctx->result.rc = 0;

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(sctx);
    close(fd);
    return NULL;

out_fail:
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(sctx);
    close(fd);
    return NULL;
}

// -------------------- assembler --------------------
static int append_file(const char *src, FILE *dst) {
    FILE *in = fopen(src, "rb");
    if (!in) return -1;
    unsigned char buf[IO_BUF_SZ];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
        if (fwrite(buf, 1, n, dst) != n) { fclose(in); return -1; }
    }
    fclose(in);
    return 0;
}

static int assemble_output(const char *outfile, int n_parts) {
    FILE *out = fopen(outfile, "wb");
    if (!out) { warnx("open %s failed", outfile); return -1; }
    char partname[64];
    for (int i = 1; i <= n_parts; i++) {
        snprintf(partname, sizeof(partname), "part_%d", i);
        if (append_file(partname, out) != 0) { warnx("append failed for %s", partname); fclose(out); return -1; }
    }
    fclose(out);
    return 0;
}

// -------------------- main --------------------
static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s -u HTTPS_URL -n NUM_PARTS -o OUTPUT_FILE\n", prog);
}

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);

    char *url_s = NULL;
    char *out_s = NULL;
    int n_parts = 0;

    int opt;
    while ((opt = getopt(argc, argv, "u:n:o:")) != -1) {
        switch (opt) {
            case 'u': url_s = optarg; break;
            case 'n': n_parts = atoi(optarg); break;
            case 'o': out_s = optarg; break;
            default: usage(argv[0]); return 1;
        }
    }
    if (!url_s || !out_s || n_parts <= 0) { usage(argv[0]); return 1; }

    url_t url;
    if (parse_https_url(url_s, &url) != 0) die("Invalid URL: %s", url_s);

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    long long total_len = https_head_get_length(&url);
    if (total_len <= 0) die("Failed to get Content-Length via HEAD");

    // compute ranges (inclusive end)
    long long base = total_len / n_parts;
    long long rem  = total_len % n_parts;

    thread_ctx_t *tctx = calloc((size_t)n_parts, sizeof(*tctx));
    pthread_t *th = calloc((size_t)n_parts, sizeof(*th));
    if (!tctx || !th) die("OOM");

    long long start = 0;
    for (int i = 0; i < n_parts; i++) {
        long long len = base + ((i == n_parts - 1) ? rem : 0);
        long long end = start + len - 1;

        part_job_t j = (part_job_t){0};
        strncpy(j.host, url.host, sizeof(j.host)-1);
        strncpy(j.path, url.path, sizeof(j.path)-1);
        j.port  = url.port;
        j.start = start;
        j.end   = end;
        j.index = i + 1;
        tctx[i].job = j;

        start = end + 1;
    }

    // spawn threads
    for (int i = 0; i < n_parts; i++) {
        if (pthread_create(&th[i], NULL, thread_download, &tctx[i]) != 0) {
            die("pthread_create failed");
        }
    }

    // join threads
    int any_err = 0;
    for (int i = 0; i < n_parts; i++) {
        pthread_join(th[i], NULL);
        if (tctx[i].result.rc != 0) {
            warnx("part_%d failed (rc=%d, wrote=%lld bytes)", tctx[i].job.index, tctx[i].result.rc, tctx[i].result.bytes_written);
            any_err = 1;
        }
    }
    if (any_err) die("One or more parts failed");

    // assemble
    if (assemble_output(out_s, n_parts) != 0) die("assemble failed");

    // optional size sanity check
    struct stat st;
    if (stat(out_s, &st) == 0 && (long long)st.st_size != total_len) {
        warnx("Warning: assembled size (%lld) != Content-Length (%lld)", (long long)st.st_size, total_len);
    }

    free(tctx);
    free(th);
    EVP_cleanup();
    ERR_free_strings();

    printf("Done. Wrote %s and part_1..part_%d\n", out_s, n_parts);
    return 0;
}
