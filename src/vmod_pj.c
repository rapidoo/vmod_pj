#include <stdlib.h>

#include "vrt.h"
#include "bin/varnishd/cache.h"

#include "vcc_if.h"
#include "global.h"
#include "md5.h"


int
init_function(struct vmod_priv *priv, const struct VCL_conf *conf)
{
	return (0);
}

const char *
vmod_hello(struct sess *sp, const char *name)
{
	char *p;
	unsigned u, v;
 	unsigned int i;

	MD5_CTX context;
	unsigned char digest[16];
	unsigned char digest2[16];
	unsigned int len = strlen (name);

	u = WS_Reserve(sp->wrk->ws, 0); /* Reserve some work space */
	p = sp->wrk->ws->f;		/* Front of workspace area */

  	MD5Init (&context);
  	MD5Update (&context, name, len);
  	MD5Final (digest, &context);

  	for (i = 0; i < 16; i++)
		sprintf (&digest2[i], "%02x", (int)digest[i]);


	v = snprintf(p, u, "%s", digest2);
	v++;
	if (v > u) {
		/* No space, reset and leave */
		WS_Release(sp->wrk->ws, 0);
		return (NULL);
	}
	/* Update work space with what we've used */
	WS_Release(sp->wrk->ws, v);
	return (p);
}
