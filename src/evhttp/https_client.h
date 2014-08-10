#ifndef __HTTPS_CLIENT_H__
#define __HTTPS_CLIENT_H__

#include <event2/event.h>
#include <event2/http.h>

#include "misc.h"

struct https_client_ctx
{
  struct event_base *evbase;
  const char *url;
  const char *body;
  void (*cb)(struct evhttp_request *, void *);
  struct keyval *headers;
};

char *
https_client_get_error(void *ctx);

int
https_client_request(struct https_client_ctx *ctx, char **errmsg);

#endif /* !__HTTPS_CLIENT_H__ */
