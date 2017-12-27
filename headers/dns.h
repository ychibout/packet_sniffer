#ifndef DNS_H
#define DNS_H

#define DNS_QR 0x8000
#define DNS_OPCODE 0x7800
#define DNS_AA 0x0400
#define DNS_TC 0x0200
#define DNS_RD 0x0100
#define DNS_RA 0x0080
#define DNS_AD 0x0020
#define DNS_CD 0x0010
#define DNS_RCODE 0x000F

struct dnshdr {
    uint16_t identification;
    uint16_t flags;
    uint16_t nb_questions;
    uint16_t nb_answersRR;
    uint16_t nb_authRR;
    uint16_t nb_addRR;
};

#endif
