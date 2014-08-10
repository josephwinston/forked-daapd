
#ifndef __LASTFM_H__
#define __LASTFM_H__

#include "db.h"

void
lastfm_login(char *path);

int
lastfm_scrobble(struct media_file_info *mfi);

#endif /* !__LASTFM_H__ */
