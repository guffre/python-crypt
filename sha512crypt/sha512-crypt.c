#define _GNU_SOURCE

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/param.h>

#include "sha512.h"

# define sha512_init_ctx(ctxp, nss_ctxp) \
  __sha512_init_ctx (ctxp)

# define sha512_process_bytes(buf, len, ctxp, nss_ctxp) \
  __sha512_process_bytes(buf, len, ctxp)

# define sha512_finish_ctx(ctxp, nss_ctxp, result) \
  __sha512_finish_ctx (ctxp, result)

/* Define our magic string to mark salt for SHA512 "encryption" replacement.  */
static const char sha512_salt_prefix[] = "$6$";

/* Prefix for optional rounds specification.  */
static const char sha512_rounds_prefix[] = "rounds=";

/* Maximum salt string length.  */
#define SALT_LEN_MAX 16
/* Default number of rounds if not explicitly specified.  */
#define ROUNDS_DEFAULT 5000
/* Minimum number of rounds.  */
#define ROUNDS_MIN 0
/* Maximum number of rounds.  */
#define ROUNDS_MAX 999999999


/* Prototypes for local functions.  */
extern char *__sha512_crypt_r (const char *key, const char *salt, char *buffer, int buflen);
extern char *__sha512_crypt (const char *key, const char *salt);


char *
__sha512_crypt_r (const char *key, const char *salt, char *buffer, int buflen)
{
  unsigned char alt_result[64]
    __attribute__ ((__aligned__ (__alignof__ (uint64_t))));
  unsigned char temp_result[64]
    __attribute__ ((__aligned__ (__alignof__ (uint64_t))));
  size_t salt_len;
  size_t key_len;
  size_t cnt;
  char *cp;
  char *copied_key = NULL;
  char *copied_salt = NULL;
  char *p_bytes;
  char *s_bytes;
  /* Default number of rounds.  */
  size_t rounds = ROUNDS_DEFAULT;
  bool rounds_custom = false;
  size_t alloca_used = 0;
  char *free_key = NULL;
  char *free_pbytes = NULL;

  /* Find beginning of salt string.  The prefix should normally always be present. Just in case it is not.  */
  if (strncmp (sha512_salt_prefix, salt, sizeof (sha512_salt_prefix) - 1) == 0)
    /* Skip salt prefix.  */
    salt += sizeof (sha512_salt_prefix) - 1;

  if (strncmp (salt, sha512_rounds_prefix, sizeof (sha512_rounds_prefix) - 1) == 0)
    {
      const char *num = salt + sizeof (sha512_rounds_prefix) - 1;
      char *endp;
      unsigned long int srounds = strtoul (num, &endp, 10);
      if (*endp == '$')
	{
	  salt = endp + 1;
	  rounds = MAX (ROUNDS_MIN, MIN (srounds, ROUNDS_MAX));
	  rounds_custom = true;
	}
    }

  salt_len = MIN (strcspn (salt, "$"), SALT_LEN_MAX);
  key_len = strlen (key);

  if ((key - (char *) 0) % __alignof__ (uint64_t) != 0)
    {
      char *tmp;
      free_key = tmp = (char *) malloc (key_len + __alignof__ (uint64_t));
	  if (tmp == NULL)
	    return NULL;

      key = copied_key =
	    memcpy (tmp + __alignof__ (uint64_t) - (tmp - (char *) 0) % __alignof__ (uint64_t), key, key_len);
      assert ((key - (char *) 0) % __alignof__ (uint64_t) == 0);
    }

  if ((salt - (char *) 0) % __alignof__ (uint64_t) != 0)
    {
      char *tmp = (char *) alloca (salt_len + __alignof__ (uint64_t));
      salt = copied_salt =
	memcpy (tmp + __alignof__ (uint64_t)
		- (tmp - (char *) 0) % __alignof__ (uint64_t),
		salt, salt_len);
      assert ((salt - (char *) 0) % __alignof__ (uint64_t) == 0);
    }

  struct sha512_ctx ctx;
  struct sha512_ctx alt_ctx;
  int i;
  printf("key:  [%s] [", key); for(i = 0; i < key_len; i++) { printf("%02x ", key[i]); }; printf("]\n");
  printf("salt: [%s] [", salt); for(i = 0; i < salt_len; i++) { printf("%02x ", salt[i]); }; printf("]\n");
  printf("rounds: %d\n", rounds);

  /* Prepare for the real work.  */
  sha512_init_ctx (&ctx, nss_ctx);

  /* Add the key string.  */
  sha512_process_bytes (key, key_len, &ctx, nss_ctx);

  /* The last part is the salt string.  This must be at most 16 characters and it ends at the first `$' character.  */
  sha512_process_bytes (salt, salt_len, &ctx, nss_ctx);


  /* Compute alternate SHA512 sum with input KEY, SALT, and KEY.  The final result will be added to the first context.  */
  sha512_init_ctx (&alt_ctx, nss_alt_ctx);

  /* Add key.  */
  sha512_process_bytes (key, key_len, &alt_ctx, nss_alt_ctx);

  /* Add salt.  */
  sha512_process_bytes (salt, salt_len, &alt_ctx, nss_alt_ctx);

  /* Add key again.  */
  sha512_process_bytes (key, key_len, &alt_ctx, nss_alt_ctx);

  /* Now get result of this (64 bytes) and add it to the other context.  */
  sha512_finish_ctx (&alt_ctx, nss_alt_ctx, alt_result);
  printf("SHA512(key+salt+key): ", key, salt, key);
  for (i = 0; i < 64; i++) { printf("%02x ", alt_result[i]); }; printf("\n");

  /* Add for any character in the key one byte of the alternate sum.  */
  for (cnt = key_len; cnt > 64; cnt -= 64) {
    sha512_process_bytes (alt_result, 64, &ctx, nss_ctx);
  }
  sha512_process_bytes (alt_result, cnt, &ctx, nss_ctx);

  /* Take the binary representation of the length of the key and for every 1 add the alternate sum, for every 0 the key.  */
  for (cnt = key_len; cnt > 0; cnt >>= 1)
    if ((cnt & 1) != 0) {
      sha512_process_bytes (alt_result, 64, &ctx, nss_ctx);
      // printf("binary representation IF\n");
      // for (i = 0; i < 64; i++) {printf("%02x ", alt_result[i]);}; printf("\n");
    }
    else {
      sha512_process_bytes (key, key_len, &ctx, nss_ctx);
      // printf("binary representation ELSE\n");
      // for (i = 0; i < key_len; i++) { printf("%02x ", key[i]);}; printf("\n");
    }

  /* Create intermediate result.  */
  sha512_finish_ctx (&ctx, nss_ctx, alt_result);
  printf("SHA512(alt_result):  ");
  for (i = 0; i < 64; i++){ printf("%02x ", alt_result[i]); }; printf("\n");

  /* Start computation of P byte sequence.  */
  sha512_init_ctx (&alt_ctx, nss_alt_ctx);

  /* For every character in the password add the entire password.  */
  for (cnt = 0; cnt < key_len; ++cnt)
    sha512_process_bytes (key, key_len, &alt_ctx, nss_alt_ctx);

  /* Finish the digest.  */
  sha512_finish_ctx (&alt_ctx, nss_alt_ctx, temp_result);
  printf("SHA512(temp_result) [p_bytes]: ");
  for (i = 0; i < 64; i++) { printf("%02x ", temp_result[i]);}; printf("\n");

  /* Create byte sequence P.  */
      free_pbytes = cp = p_bytes = (char *)malloc (key_len);
      if (free_pbytes == NULL)
	{
	  free (free_key);
	  return NULL;
	}

  for (cnt = key_len; cnt >= 64; cnt -= 64)
    cp = mempcpy (cp, temp_result, 64);
  memcpy (cp, temp_result, cnt);
  /* Start computation of S byte sequence.  */
  sha512_init_ctx (&alt_ctx, nss_alt_ctx);

  /* For every character in the password add the entire password.  */
  /* guffre NOTE: This comment is not correct. It is actually using 
     the first byte of alt_result as a number, adding 16 to it, and
     then using that sum as a random value for this loop counter.  */
  for (cnt = 0; cnt < 16 + alt_result[0]; ++cnt) {
    sha512_process_bytes (salt, salt_len, &alt_ctx, nss_alt_ctx);
  }

  /* Finish the digest.  */
  sha512_finish_ctx (&alt_ctx, nss_alt_ctx, temp_result);
  printf("SHA512(temp_result) [s_bytes]: ");
  for (i = 0; i < 64; i++) { printf("%02x ", temp_result[i]);}; printf("\n");

  /* Create byte sequence S.  */
  cp = s_bytes = alloca (salt_len);
  for (cnt = salt_len; cnt >= 64; cnt -= 64)
    cp = mempcpy (cp, temp_result, 64);
  memcpy (cp, temp_result, cnt);

  printf("p_bytes: "); for (i = 0; i < key_len; i++)  { printf("%02x ", (unsigned char)p_bytes[i]);}; printf("\n");
  printf("s_bytes: "); for (i = 0; i < salt_len; i++) { printf("%02x ", (unsigned char)s_bytes[i]);}; printf("\n");

  /* Repeatedly run the collected hash value through SHA512 to burn CPU cycles.  */
  for (cnt = 0; cnt < rounds; ++cnt) {
    /* New context.  */
    sha512_init_ctx (&ctx, nss_ctx);

    /* Add key or last result.  */
    if ((cnt & 1) != 0)
    	sha512_process_bytes (p_bytes, key_len, &ctx, nss_ctx);
    else
	    sha512_process_bytes (alt_result, 64, &ctx, nss_ctx);

    /* Add salt for numbers not divisible by 3.  */
    if (cnt % 3 != 0)
	    sha512_process_bytes (s_bytes, salt_len, &ctx, nss_ctx);

    /* Add key for numbers not divisible by 7.  */
    if (cnt % 7 != 0)
	    sha512_process_bytes (p_bytes, key_len, &ctx, nss_ctx);

    /* Add key or last result.  */
    if ((cnt & 1) != 0)
	    sha512_process_bytes (alt_result, 64, &ctx, nss_ctx);
    else
	    sha512_process_bytes (p_bytes, key_len, &ctx, nss_ctx);

    /* Create intermediate result.  */
    sha512_finish_ctx (&ctx, nss_ctx, alt_result);
  }

  /* Now we can construct the result string.  It consists of three parts.  */
  cp = __stpncpy (buffer, sha512_salt_prefix, MAX (0, buflen));
  buflen -= sizeof (sha512_salt_prefix) - 1;

  if (rounds_custom) {
    int n = snprintf (cp, MAX (0, buflen), "%s%zu$", sha512_rounds_prefix, rounds);
    cp += n;
    buflen -= n;
  }

  cp = __stpncpy (cp, salt, MIN ((size_t) MAX (0, buflen), salt_len));
  buflen -= MIN ((size_t) MAX (0, buflen), salt_len);

  if (buflen > 0) {
    *cp++ = '$';
    --buflen;
  }

  printf("SHA512(final): ");
  for (i = 0; i < 64; i++) { printf("%02x ", alt_result[i]);}; printf("\n");

  __b64_from_24bit (&cp, &buflen, alt_result[0], alt_result[21], alt_result[42], 4);
  __b64_from_24bit (&cp, &buflen, alt_result[22], alt_result[43], alt_result[1], 4);
  __b64_from_24bit (&cp, &buflen, alt_result[44], alt_result[2], alt_result[23], 4);
  __b64_from_24bit (&cp, &buflen, alt_result[3], alt_result[24], alt_result[45], 4);
  __b64_from_24bit (&cp, &buflen, alt_result[25], alt_result[46], alt_result[4], 4);
  __b64_from_24bit (&cp, &buflen, alt_result[47], alt_result[5], alt_result[26], 4);
  __b64_from_24bit (&cp, &buflen, alt_result[6], alt_result[27], alt_result[48], 4);
  __b64_from_24bit (&cp, &buflen, alt_result[28], alt_result[49], alt_result[7], 4);
  __b64_from_24bit (&cp, &buflen, alt_result[50], alt_result[8], alt_result[29], 4);
  __b64_from_24bit (&cp, &buflen, alt_result[9], alt_result[30], alt_result[51], 4);
  __b64_from_24bit (&cp, &buflen, alt_result[31], alt_result[52], alt_result[10], 4);
  __b64_from_24bit (&cp, &buflen, alt_result[53], alt_result[11], alt_result[32], 4);
  __b64_from_24bit (&cp, &buflen, alt_result[12], alt_result[33], alt_result[54], 4);
  __b64_from_24bit (&cp, &buflen, alt_result[34], alt_result[55], alt_result[13], 4);
  __b64_from_24bit (&cp, &buflen, alt_result[56], alt_result[14], alt_result[35], 4);
  __b64_from_24bit (&cp, &buflen, alt_result[15], alt_result[36], alt_result[57], 4);
  __b64_from_24bit (&cp, &buflen, alt_result[37], alt_result[58], alt_result[16], 4);
  __b64_from_24bit (&cp, &buflen, alt_result[59], alt_result[17], alt_result[38], 4);
  __b64_from_24bit (&cp, &buflen, alt_result[18], alt_result[39], alt_result[60], 4);
  __b64_from_24bit (&cp, &buflen, alt_result[40], alt_result[61], alt_result[19], 4);
  __b64_from_24bit (&cp, &buflen, alt_result[62], alt_result[20], alt_result[41], 4);
  __b64_from_24bit (&cp, &buflen, 0, 0, alt_result[63], 2);

  if (buflen <= 0)
    {
      buffer = NULL;
    }
  else
    *cp = '\0';		/* Terminate the string.  */

  /* Clear the buffer for the intermediate result so that people
     attaching to processes or reading core dumps cannot get any
     information.  We do it in this way to clear correct_words[]
     inside the SHA512 implementation as well.  */
  __sha512_init_ctx (&ctx);
  __sha512_finish_ctx (&ctx, alt_result);
  explicit_bzero (&ctx, sizeof (ctx));
  explicit_bzero (&alt_ctx, sizeof (alt_ctx));
  explicit_bzero (temp_result, sizeof (temp_result));
  explicit_bzero (p_bytes, key_len);
  explicit_bzero (s_bytes, salt_len);
  if (copied_key != NULL)
    explicit_bzero (copied_key, key_len);
  if (copied_salt != NULL)
    explicit_bzero (copied_salt, salt_len);

  free (free_key);
  free (free_pbytes);
  return buffer;
}

#ifndef _LIBC
# define libc_freeres_ptr(decl) decl
#endif
libc_freeres_ptr (static char *buffer);

/* This entry point is equivalent to the `crypt' function in Unix libcs.  */
char *
__sha512_crypt (const char *key, const char *salt)
{
  /* We don't want to have an arbitrary limit in the size of the
     password.  We can compute an upper bound for the size of the
     result in advance and so we can prepare the buffer we pass to
     `sha512_crypt_r'.  */
  static int buflen;
  int needed = (sizeof (sha512_salt_prefix) - 1
		+ sizeof (sha512_rounds_prefix) + 9 + 1
		+ strlen (salt) + 1 + 86 + 1);

  if (buflen < needed)
    {
      char *new_buffer = (char *) realloc (buffer, needed);
      if (new_buffer == NULL)
	return NULL;

      buffer = new_buffer;
      buflen = needed;
    }

  return __sha512_crypt_r (key, salt, buffer, buflen);
}

#ifndef _LIBC
static void
__attribute__ ((__destructor__))
free_mem (void)
{
  free (buffer);
}
#endif