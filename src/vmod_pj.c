#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vrt.h"
#include "bin/varnishd/cache.h"

#include "vcc_if.h"
#include "global.h"
#include "blowfish.h"

int vmod_encrypt (unsigned char *, unsigned char *, int *);
int vmod_encryptNew (char *, unsigned char *, unsigned char *, int *);
int vmod_decryptNew (char *, unsigned char *, unsigned char *, int );

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
	unsigned char digest2[10000];
	unsigned char decrypt[10000];
//	unsigned int len = strlen (name);

        unsigned char ciphertext_buffer[10000];
	unsigned char *ciphertext_string = &ciphertext_buffer[0];
	int ciphertext_len = 0;

	unsigned char *plaintext_string = name;

	// must be less than 56 bytes
        char *key = "a random number string would be a better key";

	u = WS_Reserve(sp->wrk->ws, 0); /* Reserve some work space */
	p = sp->wrk->ws->f;		/* Front of workspace area */
	
	vmod_encryptNew(key, plaintext_string, ciphertext_string, &ciphertext_len);
	
//	for (i = 0; i < ciphertext_len; i++)
//		sprintf (digest2+i*2, "%02x", (int)ciphertext_string[i]);
	
//        printf("Crypted message string is: %s", digest2);

        vmod_decryptNew (key, decrypt, ciphertext_string, ciphertext_len);

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

int
vmod_encrypt (unsigned char *plaintext_string, unsigned char *ciphertext_string, int * ciphertext_len)
   {
	   BLOWFISH_CTX ctx;
	   int n;

	   /* must be less than 56 bytes */
	   char *key = "a random number string would be a better key";
	   int keylen = strlen(key);

	   int plaintext_len = strlen(plaintext_string);

	   *ciphertext_len = 0;

	   unsigned long message_left;
	   unsigned long message_right;
	   int block_len;
	   
	   Blowfish_Init(&ctx, key, keylen);

//	   printf("Plaintext message string is: %s\n", plaintext_string);

	   /* encrypt the plaintext message string */
	 //  printf("Encrypted message string is: ");

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
		 //    printf("%lx%lx", message_left, message_right);

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

	   
		
//            printf("\n");

            return 0;

} 

int
vmod_decryptNew (char *key, unsigned char *decrypt_string, unsigned char *ciphertext_string, int ciphertext_len)
   {

	BLOWFISH_CTX ctx;
	     	   
	unsigned long message_left;
	unsigned long message_right;
	int block_len;
	int n;
        int keylen = strlen(key);

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
vmod_encryptNew (char *key, unsigned char *plaintext_string, unsigned char *ciphertext_string, int * ciphertext_len)
   {
	   BLOWFISH_CTX ctx;
	   int n;
	   int keylen = strlen(key);
	   int plaintext_len = strlen(plaintext_string);
	   unsigned long message_left;
	   unsigned long message_right;
	   int block_len;

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

            return 0;

} 

