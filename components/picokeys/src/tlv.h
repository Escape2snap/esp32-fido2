#ifndef _TLV_H_
#define _TLV_H_

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint8_t tag;
    uint16_t len;
    const uint8_t *value;
} tlv_t;

int tlv_parse(const uint8_t *buf, size_t len, tlv_t *tlv);
int tlv_next(const uint8_t *buf, size_t len, size_t *offset, tlv_t *tlv);

#endif /* _TLV_H_ */
