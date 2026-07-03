#include "tlv.h"

int tlv_parse(const uint8_t *buf, size_t len, tlv_t *tlv) {
    if (!buf || !tlv || len < 2) return -1;
    tlv->tag = buf[0];
    if (len < 2) return -1;
    if (buf[1] < 0x80) {
        tlv->len = buf[1];
        if ((size_t)(2 + tlv->len) > len) return -1;
        tlv->value = buf + 2;
        return 2 + tlv->len;
    }
    uint8_t ll = buf[1] & 0x7f;
    if (ll > 2 || (size_t)(2 + ll + tlv->len) > len) return -1;
    tlv->len = 0;
    for (uint8_t i = 0; i < ll; i++) {
        tlv->len = (tlv->len << 8) | buf[2 + i];
    }
    if ((size_t)(2 + ll + tlv->len) > len) return -1;
    tlv->value = buf + 2 + ll;
    return 2 + ll + tlv->len;
}

int tlv_next(const uint8_t *buf, size_t len, size_t *offset, tlv_t *tlv) {
    if (!buf || !tlv || !offset) return -1;
    int n = tlv_parse(buf + *offset, len - *offset, tlv);
    if (n < 0) return n;
    *offset += n;
    return 0;
}
