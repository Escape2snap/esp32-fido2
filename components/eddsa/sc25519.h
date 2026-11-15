/* Ed25519 scalar arithmetic mod l, derived from the public-domain
 * SUPERCOP ed25519 ref10 implementation (sc_reduce.c / sc_muladd.c).
 * l = 2^252 + 27742317777372353535851937790883648493.
 */
#ifndef SC25519_H
#define SC25519_H

#include <stdint.h>

void ed25519_sc_reduce(unsigned char *s);
void ed25519_sc_muladd(unsigned char *s, const unsigned char *a,
                       const unsigned char *b, const unsigned char *c);

#endif
