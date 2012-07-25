#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

#include "vrt.h"
#include "bin/varnishd/cache.h"

#include "vcc_if.h"
#include "global.h"
#include "blowfish.h"
#include "base64.h"

const char * vmod_encrypt(struct sess *sp, const char *name, const char *key );
const char * vmod_decrypt(struct sess *sp, const char *name, const char *key);
const char* vmod_response_string(struct sess *sp, const char* response_body, const char* left, const char* right);

int encryption (char *, unsigned char *, unsigned char *, unsigned char *, int *);
int decryption (char *, unsigned char *, unsigned char *);
char* get_string_between_delimiters(const char* string, const char* left, const char* right);


int
init_function(struct vmod_priv *priv, const struct VCL_conf *conf)
{
	return (0);
}

const char *
vmod_encrypt(struct sess *sp, const char *text, const char *key )
{
	char *p;
	unsigned u, v;

	unsigned char crypt64[10000];
	unsigned char ciphertext_buffer[10000];
	unsigned char *ciphertext_string = &ciphertext_buffer[0];
	int ciphertext_len = 0;

	u = WS_Reserve(sp->wrk->ws, 0); /* Reserve some work space */
	p = sp->wrk->ws->f;		/* Front of workspace area */
	
	encryption ((char*)key, text, (unsigned char*) ciphertext_string, (unsigned char*) crypt64, &ciphertext_len);
	
	v = snprintf(p, u, "%s", crypt64);
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

const char *
vmod_decrypt(struct sess *sp, const char *text, const char *key)
{
	char *p;
	unsigned u, v;
	unsigned char decrypt[10000];
	
	u = WS_Reserve(sp->wrk->ws, 0); /* Reserve some work space */
	p = sp->wrk->ws->f;		/* Front of workspace area */
	
        decryption ((char*)key, (unsigned char*) decrypt, (unsigned char*) text);

	v = snprintf(p, u, "%s", decrypt);
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

const char* 
vmod_response_string(struct sess *sp, const char* response_body, const char* left, const char* right ) {
  
  if (response_body==NULL) return NULL;
  int len = strlen(response_body);
  if (len>0) {
    return get_string_between_delimiters(response_body,left,right);
  }
  else return NULL;
  
}


char* get_string_between_delimiters(const char* string, const char* left, const char* right) {
  
  const char* beginning = strstr(string, left);
  if (beginning == NULL) return NULL;

  const char* end = strstr(string, right);
  if(end == NULL) return NULL;

  beginning += strlen(left);
  ptrdiff_t len = end - beginning;

  if (len<=0) return NULL;
  char* out = malloc(len + 1);
  strncpy(out, beginning, len);

  (out)[len] = 0;
  return out;
}





int
decryption (char *key, unsigned char *decrypt_string, unsigned char *crypt64)
   {

	BLOWFISH_CTX ctx;
	     	   
	unsigned long message_left;
	unsigned long message_right;
	int block_len;
	int n,i;
        int keylen = strlen(key);
   	unsigned char ciphertext_buffer[10000];
	unsigned char *ciphertext_string = &ciphertext_buffer[0];
	int ciphertext_len;

	decode_base64( crypt64, ciphertext_string);
        ciphertext_len = strlen (ciphertext_string);

	Blowfish_Init(&ctx, key, keylen);

	while(ciphertext_len)
	{
		message_left = message_right = 0UL;

		for (block_len = 0; block_len < 4; block_len++)
		{
		  message_left = message_left << 8;
		  message_left += *ciphertext_string++;
		  if (ciphertext_len)
		   ciphertext_len--;
		}
		for (block_len = 0; block_len < 4; block_len++)
		{
		   message_right = message_right << 8;
		   message_right += *ciphertext_string++;
		   if (ciphertext_len)
		   ciphertext_len--;
		}

		Blowfish_Decrypt(&ctx, &message_left, &message_right);


  	  	/* save the results of decryption */
		*decrypt_string++ = (unsigned char)(message_left >> 24);
		*decrypt_string++ = (unsigned char)(message_left >> 16);
		*decrypt_string++ = (unsigned char)(message_left >> 8);
		*decrypt_string++ = (unsigned char)message_left;
		*decrypt_string++ = (unsigned char)(message_right >> 24);
		*decrypt_string++ = (unsigned char)(message_right >> 16);
		*decrypt_string++ = (unsigned char)(message_right >> 8);
		*decrypt_string++ = (unsigned char)message_right;

	}

}


int
encryption (char *key, unsigned char *plaintext_string, unsigned char *ciphertext_string, unsigned char *crypt64, int * ciphertext_len)
   {
	   BLOWFISH_CTX ctx;
	   int n;
	   int keylen = strlen(key);
	   int plaintext_len = strlen(plaintext_string);
	   unsigned long message_left;
	   unsigned long message_right;
	   int block_len;
           char * ciphertext_string_ori = ciphertext_string;

      	   *ciphertext_len = 0;
	   
	   Blowfish_Init(&ctx, key, keylen);

	   while (plaintext_len)
	   {
		     message_left = message_right = 0UL;

		   /* crack the message string into a 64-bit block (ok, really two 32-bit blocks); pad with zeros if necessary */
		     for (block_len = 0; block_len < 4; block_len++)
		     {
			       message_left = message_left << 8;
			       if (plaintext_len)
			       {
				   message_left += *plaintext_string++;
				   plaintext_len--;
			       }
			       else message_left += 0;
		     }
		     for (block_len = 0; block_len < 4; block_len++)
		     {
			       message_right = message_right << 8;
			       if (plaintext_len)
			       {
				   message_right += *plaintext_string++;
				   plaintext_len--;
			       }
			       else message_right += 0;
		     }
          

		    /* encrypt and print the results */
		     Blowfish_Encrypt(&ctx, &message_left, &message_right);

		   /* save the results for decryption below */
		     *ciphertext_string++ = (unsigned char)(message_left >> 24);
		     *ciphertext_string++ = (unsigned char)(message_left >> 16);
		     *ciphertext_string++ = (unsigned char)(message_left >> 8);
		     *ciphertext_string++ = (unsigned char)message_left;
		     *ciphertext_string++ = (unsigned char)(message_right >> 24);
		     *ciphertext_string++ = (unsigned char)(message_right >> 16);
		     *ciphertext_string++ = (unsigned char)(message_right >> 8);
		     *ciphertext_string++ = (unsigned char)message_right;
		     *ciphertext_len += 8;		    
	    }

 	    encode_base64(*ciphertext_len, ciphertext_string_ori, crypt64 );

            return 0;

} 



