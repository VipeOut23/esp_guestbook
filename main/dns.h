#ifndef __DNS_H
#define __DNS_H


#include "user_interface.h"
#include "dns_def.h"

enum dns_error {
        DNSE_OK,
        DNSE_ERROR,
        DNSE_LABEL_LEN_OVERFLOW,
        DNSE_NAME_LEN_OVERFLOW,
        DNSE_PACKET_TOO_SMALL,
        DNSE_UNIMPLEMENTED
};

/**
 * Holds the last dns_error
 */
extern enum dns_error dns_error;

/**
 * Add records here, the server tries to deliver them
 */
extern struct resource_record *dns_records;
/**
 * Also keep track of how many records there are
 */
extern uint16 dns_record_count;

bool ICACHE_FLASH_ATTR dns_parse(char *data, uint16 len);
void ICACHE_FLASH_ATTR dns_dump();
char* ICACHE_FLASH_ATTR dns_errstr();

#endif // __DNS_H
