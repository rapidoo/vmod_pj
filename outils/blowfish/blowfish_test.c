#include <stdio.h>
#include <string.h>
#include "blowfish.h"
#include "base64.h"

int encryption (char *, unsigned char *, unsigned char *, unsigned char *, int *);
int decryption (char *, unsigned char *, unsigned char *);

int
main (void)
   {
	   BLOWFISH_CTX ctx;
	   int n, i;

	   // must be less than 56 bytes
	   char *key = "91682bc88e5e5c0155cbca994d59d343";

  	   unsigned char *plaintext_string = "SecretMessage";
	   int plaintext_len = strlen(plaintext_string);

           unsigned char decrypt[10000];
           unsigned char crypt64[10000];
           unsigned char decrypt64[10000];
	   
	   unsigned char ciphertext_buffer[10000];
	   unsigned char *ciphertext_string = &ciphertext_buffer[0];
	   int ciphertext_len = 0;
	   int ciphertext_len64 = 0;


	   printf("Plaintext message string is: %s\n", plaintext_string);

	   encryption (key, plaintext_string, ciphertext_string, crypt64, &ciphertext_len);

	   printf("Encrypted 64 string is: %s\n", crypt64);

           decryption (key, decrypt, crypt64);

           printf("message Plain Text decode blowfish is: %s \n", decrypt);


	return 0;
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


