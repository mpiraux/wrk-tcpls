#include <sys/ioctl.h>
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

static void *socket_readable = NULL;
static void *socket_writeable = NULL;

void *rapido_init(void *r, void *w) {
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
#if !defined(OPENSSL_NO_ENGINE)
    /* Load all compiled-in ENGINEs */
    ENGINE_load_builtin_engines();
    ENGINE_register_all_ciphers();
    ENGINE_register_all_digests();
#endif
    res_init();
    socket_readable = r;
    socket_writeable = w;
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

        c->session = rapido_new_session(ctx, false, host, DEBUG ? stderr : NULL);
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
    int ret = recv(c->fd, recvbuf, processed, MSG_WAITALL);
    if (ret > 0) {
        processed = ret;
        size_t recvd_len = ret;
        ret = rapido_client_process_handshake(c->session, 0, recvbuf, &processed);
        assert(processed == recvd_len);
    }
    if (!ptls_handshake_is_complete(c->session->tls)) {
        return RETRY;
    }
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
size_t rapido_send(connection *c, uint64_t current_time) {
    size_t total_written = 0;
    rapido_array_iter(&c->session->connections, i, rapido_connection_t *connection, {
        int is_blocked = false;
        int wants_to_send = rapido_connection_wants_to_send(c->session, connection, current_time, &is_blocked);
        if (wants_to_send) {
            uint8_t sendbuf[16384 + 256];
            size_t sendbuf_len = sizeof(sendbuf);
            rapido_prepare_data(c->session, connection->connection_id, current_time, sendbuf, &sendbuf_len);
            size_t written = write(connection->socket, sendbuf, sendbuf_len);
            if (written != sendbuf_len) {
                debug("Partial write!");
                return ERROR;
            }
            total_written += written;
        }
    });
    return total_written;
}
//File descriptor has some data available for conection c
//will write this data in c->buf and write the amount of bytes written in *sz
status rapido_read(connection *c, size_t *sz) {
    debug("Called %s with sz: %zu", __FUNCTION__, *sz);
    if (c->session->is_closed) {
        return ERROR;
    }
    if (!ptls_handshake_is_complete(c->session->tls)) {
        return ERROR;
    }
    uint64_t current_time = get_usec_time();

    rapido_array_iter(&c->session->connections, i, rapido_connection_t *connection, {
        uint8_t recvbuf[16384 + 256];
        int recvd = recv(connection->socket, recvbuf, sizeof(recvbuf), MSG_DONTWAIT);
        debug("Read %d bytes from cid %d", recvd, connection->connection_id);
        if (recvd <= 0) continue;
        assert(recvd > 0);
        size_t processed = recvd;
        if (!ptls_handshake_is_complete(connection->tls)) {
            rapido_client_process_handshake(c->session, connection->connection_id, recvbuf, &processed);         
        } else {
            rapido_process_incoming_data(c->session, connection->connection_id, current_time, recvbuf, &processed);
        }
        if (processed != recvd) {
            debug("Did not process all bytes");
            return ERROR;
        }
    });

    *sz = 0;
    rapido_queue_drain(&c->session->pending_notifications, rapido_application_notification_t *notification, {
        if (notification->notification_type == rapido_stream_has_data) {
            size_t read_len = sizeof(c->buf) - *sz;
            void *ptr = rapido_read_stream(c->session, 0, &read_len);
            do {
                memcpy(c->buf + *sz, ptr, read_len);
                *sz += read_len;
                read_len = sizeof(c->buf) - *sz;
                ptr = rapido_read_stream(c->session, 0, &read_len);
            } while (ptr != NULL);
            printf("Req read: %lu\n", get_usec_time());
        } else if (notification->notification_type == rapido_new_remote_address) {
            printf("Creating one more connection\n");
            rapido_connection_id_t cid = rapido_create_connection(c->session, 1, notification->address_id);
            rapido_array_iter(&c->session->connections, i, rapido_connection_t *connection, {
                if (connection->connection_id == cid) {
                    aeCreateFileEvent(c->thread->loop, connection->socket, AE_READABLE, socket_readable, c);
                }
            });
        }
        if (*sz >= sizeof(c->buf)) {
            break;
        }
    });
    debug("Wrote %zu bytes for the application to read\n", *sz);
   
    if (!c->session->is_closed) {
        rapido_send(c, current_time);
    }
    return *sz == 0 ? AGAIN : OK;
}
//File descriptor is ready to write sz bytes into buffer buf. The amount actually written is returned in *wrote 
status rapido_write(connection *c, char *buf, size_t sz, size_t *wrote) {
    debug("Called %s with buf: %p, sz: %zu, wrote: %p", __FUNCTION__, buf, sz, wrote);
    uint64_t current_time = get_usec_time();
    printf("Req write: %lu\n", current_time);
    rapido_stream_id_t stream_id = rapido_open_stream(c->session);
    rapido_add_to_stream(c->session, stream_id, buf, sz);
    rapido_connection_id_t fastest_conn = 0;
    {  // Find the fastest connection to send the request
        uint64_t shortest_time_to_send = UINT64_MAX;
        rapido_array_iter(&c->session->connections, connection_id, rapido_connection_t *connection, {
            rapido_attach_stream(c->session, stream_id, connection_id);
            if (rapido_connection_wants_to_send(c->session, connection, current_time, NULL)) {
                rapido_connection_info_t conn_info = { 0 };
                rapido_connection_get_info(c->session, connection_id, &conn_info);
                uint64_t time_to_send = rapido_time_to_transfer(conn_info, sz);
                if (time_to_send < shortest_time_to_send) {
                    shortest_time_to_send = time_to_send;
                    fastest_conn = connection_id;
                }
            }
            rapido_detach_stream(c->session, stream_id, connection_id);
        });
    }
    rapido_attach_stream(c->session, stream_id, fastest_conn);
    rapido_close_stream(c->session, stream_id);
    assert(rapido_send(c, current_time) > 0);
    *wrote = sz; // TODO: Handle partial writes
    return OK;
}
//File descriptor is readable, should return the number of bytes actually available (e.g. for SSL calls SSL_Pending
size_t rapido_readable(connection *c) {
    debug("Called %s", __FUNCTION__);
    size_t n = 0;
    rapido_array_iter(&c->session->connections, i, rapido_connection_t *connection, {
        size_t cn;
        if (ioctl(connection->socket, FIONREAD, &cn) != -1) {
            n += cn;
        }
    });
    return n;
}