#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/pem.h>
#include <resolv.h>
#include "wrk.h"
#include "tcpls.h"
#include "picotls.h"
#include "picotls/openssl.h"

static uint64_t get_usec_time() {
    struct timespec tv;
    assert(clock_gettime(CLOCK_REALTIME, &tv) == 0);
    return tv.tv_sec * 1000000 + tv.tv_nsec / 1000;
}

void *rapido_init() {
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
#if !defined(OPENSSL_NO_ENGINE)
    /* Load all compiled-in ENGINEs */
    ENGINE_load_builtin_engines();
    ENGINE_register_all_ciphers();
    ENGINE_register_all_digests();
#endif
    res_init();
    return "OK";
}

//Connect connection c to host
status rapido_connect(connection *c, char *host) {
    if (c->fd < 0) {
        debug("rapido_connect: c->fd is not valid");
        return ERROR;
    }
    if (c->session == NULL) {   
        ptls_key_exchange_algorithm_t **key_exchanges = calloc(128, sizeof(ptls_key_exchange_algorithm_t *));
        key_exchanges[0] = &ptls_openssl_secp256r1;
        ptls_cipher_suite_t **cipher_suites = calloc(128, sizeof(ptls_cipher_suite_t *));
        ptls_context_t *ctx = malloc(sizeof(ptls_context_t));
        ctx->random_bytes = ptls_openssl_random_bytes;
        ctx->get_time = &ptls_get_time;
        ctx->key_exchanges = key_exchanges;
        ctx->cipher_suites = cipher_suites;
        size_t i;
        for (i = 0; ptls_openssl_cipher_suites[i] != NULL; ++i)
            cipher_suites[i] = ptls_openssl_cipher_suites[i];

        c->session = rapido_new_session(ctx, false, host, NULL);
        struct sockaddr_storage local_address, peer_address;
        socklen_t local_address_len = sizeof(struct sockaddr_storage), peer_address_len = sizeof(struct sockaddr_storage);
        if (getsockname(c->fd, &local_address, &local_address_len)) {
            debug("rapido_connect: getsockname error");
            return ERROR;
        }
        if (getpeername(c->fd, &peer_address, &peer_address_len)) {
            debug("rapido_connect: getpeername error");
            return ERROR;
        }
        rapido_address_id_t laid = rapido_add_address(c->session, &local_address, local_address_len);
        rapido_address_id_t raid = rapido_add_remote_address(c->session, &peer_address, peer_address_len);
        rapido_connection_id_t connection_id = rapido_client_add_connection(c->session, c->fd, laid, raid);
    }
    uint8_t recvbuf[16384 + 256];
    size_t processed = sizeof(recvbuf);
    int ret = recv(c->fd, recvbuf, processed, 0);
    if (ret == -1 && errno == EAGAIN)
        return RETRY;
    processed = ret;
    ret = rapido_client_process_handshake(c->session, 0, recvbuf, &processed);
    uint8_t sendbuf[16384 + 256];
    size_t sendbuf_len = sizeof(sendbuf);
    rapido_prepare_data(c->session, 0, get_usec_time(), sendbuf, &sendbuf_len);
    if (sendbuf_len > 0) {
        size_t written = write(c->fd, sendbuf, sendbuf_len);
        if (written != sendbuf_len) {
            debug("Partial write!");
            return ERROR;
        }
    }
    if (!ptls_handshake_is_complete(c->session->tls)) {
        return RETRY;
    }
    return OK;
}
//Close connection c
status rapido_close(connection *c) {
    debug("Called %s", __FUNCTION__);
    if (!c->session->is_closed) {
        rapido_close_session(c->session, 0);
    }
    free(c->session->tls_ctx->key_exchanges);
    free(c->session->tls_ctx->cipher_suites);
    free(c->session->tls_ctx);
    rapido_session_free(c->session);
    free(c->session);
    c->session = NULL;
    return OK;
}
//File descriptor has some data available for conection c
//will write this data in c->buf and write the amount of bytes written in *sz
status rapido_read(connection *c, size_t *sz) {
    if (c->session->is_closed) {
        return ERROR;
    }
    if (!ptls_handshake_is_complete(c->session->tls)) {
        return ERROR;
    }
    uint64_t current_time = get_usec_time();
    uint8_t recvbuf[16384 + 256];
    int recvd = read(c->fd, recvbuf, sizeof(recvbuf));
    size_t processed = recvd;
    rapido_process_incoming_data(c->session, 0, get_usec_time(), recvbuf, &processed);
    if (processed != recvd) {
        debug("Did not process all bytes");
        return ERROR;
    }
    *sz = 0;
    rapido_queue_drain(&c->session->pending_notifications, rapido_application_notification_t *notification, {
        if (notification->notification_type == rapido_stream_has_data) {
            size_t read_len = sizeof(c->buf) - *sz;
            void *ptr = rapido_read_stream(c->session, 0, &read_len);
            memcpy(c->buf + *sz, ptr, read_len);
            *sz += read_len;
        }
        if (*sz >= sizeof(c->buf)) {
            break;
        }
    });
   
    if (!c->session->is_closed) {
        uint8_t sendbuf[16384 + 256];
        size_t sendbuf_len = sizeof(sendbuf);
        rapido_prepare_data(c->session, 0, current_time, sendbuf, &sendbuf_len);
        size_t written = write(c->fd, sendbuf, sendbuf_len);
        if (written != sendbuf_len) {
            debug("Partial write!");
            return ERROR;
        }
    }
    return *sz == 0 ? RETRY : OK;
}
//File descriptor is ready to write sz bytes into buffer buf. The amount actually written is returned in *wrote 
status rapido_write(connection *c, char *buf, size_t sz, size_t *wrote) {
    debug("Called %s with buf: %p, sz: %zu, wrote: %p", __FUNCTION__, buf, sz, wrote);
    rapido_stream_id_t stream_id = rapido_open_stream(c->session);
    rapido_add_to_stream(c->session, stream_id, buf, sz);
    rapido_attach_stream(c->session, stream_id, 0);
    rapido_close_stream(c->session, stream_id);
    uint8_t sendbuf[16384 + 256];
    size_t sendbuf_len = sizeof(sendbuf);
    rapido_prepare_data(c->session, 0, get_usec_time(), sendbuf, &sendbuf_len);
    size_t written = write(c->fd, sendbuf, sendbuf_len);
    if (written != sendbuf_len) {
        debug("Partial write!");
        return ERROR;
    }
    *wrote = sz; // TODO: Handle partial writes
    return OK;
}
//File descriptor is readable, should return the number of bytes actually available (e.g. for SSL calls SSL_Pending
size_t rapido_readable(connection *c) {
    debug("Called %s", __FUNCTION__);
    return ERROR;
}