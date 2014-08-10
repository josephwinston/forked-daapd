/*
 * Large parts copied from the libevent sample https client:
 *
 * Copyright (c) 2000-2007 Niels Provos <provos@citi.umich.edu>
 * Copyright (c) 2007-2012 Niels Provos and Nick Mathewson
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <sys/socket.h>
#include <netinet/in.h>

#include <event2/bufferevent_ssl.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <event2/http.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "https_client.h"

/* ------------------------------ HTTPS CLIENT ----------------------------- */
/*           Also supports http. TODO: Host certificate validation           */

char *
https_client_get_error(void *ctx)
{
  /* If req is NULL, it means an error occurred, but
   * sadly we are mostly left guessing what the error
   * might have been.  We'll do our best... */
  struct bufferevent *bev = (struct bufferevent *) ctx;
  unsigned long oslerr;
  int errcode = EVUTIL_SOCKET_ERROR();
  char buffer[256];

  /* Print out the OpenSSL error queue that libevent
   * squirreled away for us, if any. */
  while ((oslerr = bufferevent_get_openssl_error(bev))) {
    ERR_error_string_n(oslerr, buffer, sizeof(buffer));
    return strdup(buffer);
  }

  /* If the OpenSSL error queue was empty, maybe it was a
   * socket error; let's try printing that. */
  return evutil_socket_error_to_string(errcode);
}

int
https_client_request(struct https_client_ctx *ctx, char **errmsg)
{
  struct evhttp_uri *http_uri;
  struct bufferevent *bev;
  struct evhttp_connection *evcon;
  struct evhttp_request *req;
  struct evkeyvalq *output_headers;
  struct evbuffer *output_buffer;
  const char *scheme, *host, *path, *query;
  char uri[256];
  char content_len[8];
  int port;
  int ret;
  SSL_CTX *ssl_ctx;
  SSL *ssl;

  *errmsg = NULL;

  http_uri = evhttp_uri_parse(ctx->url);
  if (http_uri == NULL) {
    *errmsg = "Malformed url";
    return -1;
  }

  scheme = evhttp_uri_get_scheme(http_uri);
  if (scheme == NULL || (strcasecmp(scheme, "https") != 0 &&
                         strcasecmp(scheme, "http") != 0)) {
    *errmsg = "URL must be http or https";
    return -1;
  }

  host = evhttp_uri_get_host(http_uri);
  if (host == NULL) {
    *errmsg = "URL must have a host";
    return -1;
  }

  port = evhttp_uri_get_port(http_uri);
  if (port == -1) {
    port = (strcasecmp(scheme, "http") == 0) ? 80 : 443;
  }

  path = evhttp_uri_get_path(http_uri);
  if (path == NULL) {
    path = "/";
  }

  query = evhttp_uri_get_query(http_uri);
  if (query == NULL) {
    snprintf(uri, sizeof(uri) - 1, "%s", path);
  } else {
    snprintf(uri, sizeof(uri) - 1, "%s?%s", path, query);
  }
  uri[sizeof(uri) - 1] = '\0';

  // Initialize OpenSSL
  SSL_library_init();
  ERR_load_crypto_strings();
  SSL_load_error_strings();
  OpenSSL_add_all_algorithms();

  /* Create a new OpenSSL context */
  ssl_ctx = SSL_CTX_new(SSLv23_method());
  if (!ssl_ctx)
    {
      *errmsg = "Could not create SSL context";
      return -1;
    }

  // Create OpenSSL bufferevent and stack evhttp on top of it
  ssl = SSL_new(ssl_ctx);
  if (ssl == NULL)
    {
      *errmsg = "Could not create SSL bufferevent";
      return -1;
    }

  // Set hostname for SNI extension
  SSL_set_tlsext_host_name(ssl, host);

  if (strcasecmp(scheme, "http") == 0)
    {
      bev = bufferevent_socket_new(ctx->evbase, -1, BEV_OPT_CLOSE_ON_FREE);
    } 
  else
    {
      bev = bufferevent_openssl_socket_new(ctx->evbase, -1, ssl,
        BUFFEREVENT_SSL_CONNECTING,
        BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
    }

  if (bev == NULL)
    {
      *errmsg = "Could not create bufferevent";
      return -1;
    }

  bufferevent_openssl_set_allow_dirty_shutdown(bev, 1);

  evcon = evhttp_connection_base_bufferevent_new(ctx->evbase, NULL, bev, host, port);
  if (evcon == NULL)
    {
      *errmsg = "Could not create evcon";
      return -1;
    }

  // Fire off the request
  req = evhttp_request_new(ctx->cb, bev);
  if (req == NULL)
    {
      *errmsg = "Could not create request";
      evhttp_connection_free(evcon);
      return -1;
    }

  output_headers = evhttp_request_get_output_headers(req);
  evhttp_add_header(output_headers, "Host", host);
  evhttp_add_header(output_headers, "Connection", "close");
  evhttp_add_header(output_headers, "User-Agent", "forked-daapd");
  evhttp_add_header(output_headers, "Accept-Charset", "utf-8");
// TODO add custom headers
  evhttp_add_header(output_headers, "Content-Type", "application/x-www-form-urlencoded");

  if (ctx->body)
    {
      output_buffer = evhttp_request_get_output_buffer(req);
      evbuffer_add(output_buffer, ctx->body, strlen(ctx->body));
      snprintf(content_len, sizeof(content_len), "%d", strlen(ctx->body));
      evhttp_add_header(output_headers, "Content-Length", content_len);
    }

  ret = evhttp_make_request(evcon, req, ctx->body ? EVHTTP_REQ_POST : EVHTTP_REQ_GET, uri);
  if (ret != 0)
    {
      *errmsg = "Could not make request";
      evhttp_connection_free(evcon);
      return -1;
    }

  return 0;
}

