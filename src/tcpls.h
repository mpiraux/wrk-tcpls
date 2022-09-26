#ifndef TCPLS_H
#define TCPLS_H

#include <assert.h>
#include "net.h"
#include "rapido.h"

#define DEBUG 0
#if DEBUG
#define debug(s) (printf("[%f - %p] " s "\n", (float)time_us() / 1000000, c))
#define debug(s, ...) (printf("[%f - %p] " s "\n", (float)time_us() / 1000000, c, ##__VA_ARGS__))
#else
#define debug(...)
#endif

//Called once to initialize the Rapido library
void *rapido_init();

//Connect connection c to host
status rapido_connect(connection *c, char *host);
//Close connection c
status rapido_close(connection *c);
//File descriptor has some data available for conection c
//will write this data in c->buf and write the amount of bytes written in *sz
status rapido_read(connection *c, size_t *sz);
//File descriptor is ready to write sz bytes into buffer buf. The amount actually written is returned in *wrote 
status rapido_write(connection *c, char *buf, size_t sz, size_t *wrote);
//File descriptor is readable, should return the number of bytes actually available (e.g. for SSL calls SSL_Pending
size_t rapido_readable(connection *);

//rapido_writable could be written also if needed

#endif /* TCPLS_H */
