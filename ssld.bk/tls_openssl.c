/*
 * Standalone TLS/OpenSSL implementation for ircu2 TLS daemon
 * Adapted for use in the TLS daemon, not IRCd.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <sys/uio.h>
#include <errno.h>
#include "ircd_tls.h"
#include "log.h"

static SSL_CTX *server_ctx = NULL;
static SSL_CTX *client_ctx = NULL;
static const EVP_MD *fp_digest;

static void ssl_log_error(const char *msg)
{
    unsigned long err;
    char buf[256];
    err = ERR_get_error();
    if (err) {
        ERR_error_string_n(err, buf, sizeof(buf));
        log_write(LOG_LEVEL_ERROR, "OpenSSL %s: %s", msg, buf);
        while ((err = ERR_get_error()) != 0) {
            ERR_error_string_n(err, buf, sizeof(buf));
            log_write(LOG_LEVEL_ERROR, " ... %s", buf);
        }
    } else {
        log_write(LOG_LEVEL_ERROR, "Unknown OpenSSL failure: %s", msg);
    }
}

static int verify_callback(int preverify_ok, X509_STORE_CTX *ctx)
{
  if (!preverify_ok /* && feature_bool(FEAT_TLS_ALLOW_SELFSIGNED) */)
  {
    int err = X509_STORE_CTX_get_error(ctx);
    if (err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT ||
        err == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN)
      return 1;
  }
  return preverify_ok;
}

int ircd_tls_init(const char *certfile, const char *keyfile)
{
    SSL_CTX *new_server_ctx = NULL;
    SSL_CTX *new_client_ctx = NULL;

    SSL_library_init();
    SSL_load_error_strings();

    if (!RAND_poll()) {
        ssl_log_error("RAND_poll failed");
        return 1;
    }

    new_server_ctx = SSL_CTX_new(TLS_server_method());
    if (!new_server_ctx) {
        ssl_log_error("SSL_CTX_new failed for server");
        return 2;
    }

    new_client_ctx = SSL_CTX_new(TLS_client_method());
    if (!new_client_ctx) {
        ssl_log_error("SSL_CTX_new failed for client");
        SSL_CTX_free(new_server_ctx);
        return 2;
    }

    if (!(SSL_CTX_use_certificate_chain_file(new_server_ctx, certfile) == 1 &&
          SSL_CTX_use_certificate_chain_file(new_client_ctx, certfile) == 1)) {
        ssl_log_error("unable to load certificate file");
        goto fail;
    }

    if (!(SSL_CTX_use_PrivateKey_file(new_server_ctx, keyfile, SSL_FILETYPE_PEM) == 1 &&
          SSL_CTX_use_PrivateKey_file(new_client_ctx, keyfile, SSL_FILETYPE_PEM) == 1)) {
        ssl_log_error("unable to load private key");
        goto fail;
    }

    if (!(SSL_CTX_check_private_key(new_server_ctx) == 1 &&
          SSL_CTX_check_private_key(new_client_ctx) == 1)) {
        ssl_log_error("certificate and private key do not match");
        goto fail;
    }

    /* Set protocol versions. */
    SSL_CTX_set_min_proto_version(new_server_ctx, TLS1_2_VERSION);
    SSL_CTX_set_min_proto_version(new_client_ctx, TLS1_2_VERSION);

    /* Configure verification */
    SSL_CTX_set_verify(new_server_ctx, SSL_VERIFY_PEER|SSL_VERIFY_CLIENT_ONCE, verify_callback);
    SSL_CTX_set_verify(new_client_ctx, SSL_VERIFY_PEER|SSL_VERIFY_CLIENT_ONCE, verify_callback);

    if (server_ctx)
        SSL_CTX_free(server_ctx);
    if (client_ctx)
        SSL_CTX_free(client_ctx);
    server_ctx = new_server_ctx;
    client_ctx = new_client_ctx;

    fp_digest = EVP_sha256();

    return 0;

fail:
    if (new_server_ctx)
        SSL_CTX_free(new_server_ctx);
    if (new_client_ctx)
        SSL_CTX_free(new_client_ctx);
    return 6;
}

void ircd_tls_cleanup(void)
{
    if (server_ctx)
        SSL_CTX_free(server_ctx);
    if (client_ctx)
        SSL_CTX_free(client_ctx);
    server_ctx = NULL;
    client_ctx = NULL;
}

struct TlsSession *tls_session_create(int fd, int is_server)
{
    struct TlsSession *sess = calloc(1, sizeof(struct TlsSession));
    if (!sess)
        return NULL;
    sess->fd = fd;
    sess->rexmit = NULL;
    sess->rexmit_len = 0;
    sess->ssl = SSL_new(is_server ? server_ctx : client_ctx);
    if (!sess->ssl) {
        ssl_log_error("unable to create SSL session");
        free(sess);
        return NULL;
    }
    SSL_set_fd((SSL *)sess->ssl, fd);
    if (is_server)
        SSL_set_accept_state((SSL *)sess->ssl);
    else
        SSL_set_connect_state((SSL *)sess->ssl);
    return sess;
}

void tls_session_free(struct TlsSession *sess)
{
    if (!sess) return;

    SSL *ssl = (SSL *)sess->ssl;
    if (ssl) {
        SSL_set_shutdown(ssl, SSL_RECEIVED_SHUTDOWN);
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    sess->session_id = 0;  // Clear session ID
    free(sess);
}

int tls_session_handshake(struct TlsSession *sess)
{
    X509 *cert;
    unsigned char buf[EVP_MAX_MD_SIZE];
    unsigned int len;

    if (!sess || !sess->ssl) return -1;
    SSL *ssl = (SSL *)sess->ssl;
    int ret = SSL_do_handshake(ssl);

    if (ret == 1) {
        cert = SSL_get_peer_certificate(ssl);
        if (cert) {
            log_write(LOG_LEVEL_DEBUG, "SSL_get_peer_certificate success for s=%d", sess->fd);
            len = sizeof(buf);
            log_write(LOG_LEVEL_DEBUG, "Calculating fingerprint for s=%d", sess->fd);
            int res = X509_digest(cert, fp_digest, buf, &len);
            log_write(LOG_LEVEL_DEBUG, "X509_digest returned %d for s=%d, len=%u", res, sess->fd, len);
            X509_free(cert);
            log_write(LOG_LEVEL_DEBUG, "X509_free called for s=%d", sess->fd);
            if (res) {
                log_write(LOG_LEVEL_DEBUG, "X509_digest failed for s=%d: %d", sess->fd, res);
            }

            if (len == 32) { 
                /* Convert fingerprint to lowercase hex */
                char *p = sess->fingerprint;
                for (unsigned int i = 0; i < len; i++) {
                    sprintf(p + (i * 2), "%02x", buf[i]);
                }
                p[len * 2] = '\0';
                log_write(LOG_LEVEL_DEBUG, "Fingerprint for s=%d: %s", sess->fd, sess->fingerprint);
            } else {
                memset(sess->fingerprint, 0, sizeof(sess->fingerprint));
                log_write(LOG_LEVEL_ERROR, "X509_digest failed for s=%d", sess->fd);
            }
        }

        return 1; // handshake complete
    }

    int err = SSL_get_error(ssl, ret);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
        return IO_BLOCKED; // handshake in progress
    ssl_log_error("SSL handshake failed");
    return IO_FAILURE; // handshake failed
}

ssize_t tls_session_read(struct TlsSession *sess, void *buf, size_t len)
{
    log_write(LOG_LEVEL_DEBUG, "Reading %zu bytes from TLS session", len);
    if (!sess || !sess->ssl) return -1;
    SSL *ssl = (SSL *)sess->ssl;
    int ret = SSL_read(ssl, buf, len);
    if (ret > 0)
        return ret;
    int err = SSL_get_error(ssl, ret);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
        return IO_BLOCKED; // Would block
    ssl_log_error("SSL_read failed");
    return IO_FAILURE;
}

ssize_t tls_session_sendv(struct TlsSession *sess, struct iovec *iov, int iovcnt)
{
    int ii, res;
    ssize_t total_sent = 0;
    SSL *ssl = (SSL *)sess->ssl;

    // Handle retransmit first
    if (sess->rexmit && sess->rexmit_len > 0) {
        res = SSL_write(ssl, sess->rexmit, sess->rexmit_len);
        if (res <= 0) {
            int err = SSL_get_error(ssl, res);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
                return total_sent; // Would block, try again later
            ssl_log_error("SSL_write failed (retransmit)");
            return IO_FAILURE; // Fatal error
        }
        if ((size_t)res < sess->rexmit_len) {
            sess->rexmit += res;
            sess->rexmit_len -= res;
            return total_sent + res;
        }
        // Full retransmit sent
        sess->rexmit = NULL;
        sess->rexmit_len = 0;
        total_sent += res;
    }

    // Now send new iovecs
    for (ii = 0; ii < iovcnt; ++ii) {
        res = SSL_write(ssl, iov[ii].iov_base, iov[ii].iov_len);
        if (res > 0) {
            total_sent += res;
            if ((size_t)res < iov[ii].iov_len) {
                // Partial send, store for retransmit
                sess->rexmit = (char *)iov[ii].iov_base + res;
                sess->rexmit_len = iov[ii].iov_len - res;
                return total_sent;
            }
            continue;
        }
        int err = SSL_get_error(ssl, res);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            sess->rexmit = iov[ii].iov_base;
            sess->rexmit_len = iov[ii].iov_len;
            return total_sent;
        }
        ssl_log_error("SSL_write failed");
        sess->rexmit = iov[ii].iov_base;
        sess->rexmit_len = iov[ii].iov_len;
        return IO_FAILURE;
    }
    return total_sent;
}
