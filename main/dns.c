/* LWIP definitions */
#define LWIP_RAW 1
#define LWIP_TCP 1
#define LWIP_UDP 1
#define NO_SYS   0

#include "dns.h"
#include "dns_def.h"

#include "os_type.h"
#include "user_interface.h"
#include "lwip/def.h"

/* OpCodes */
#define IS_REPLY   (header[0] & 0b00000001)
#define IS_QUERY  ((header[0] & 0b00011110) == 0b10)
#define IS_STATUS ((header[0] & 0b00011110) == 0b100)
#define IS_NOTIFY ((header[0] & 0b00011110) == 0b1000)
#define IS_UPDATE ((header[0] & 0b00011110) == 0b1010)
/* Flags */
#define IS_TRUNC  ((header[0] & 0b01000000))


/* Packet content */
static uint8  id[2];
static uint8  header[2];
static uint16 qdcount;
static uint16 ancount;
static uint16 nscount;
static uint16 arcount;
static struct question questions[MAX_QUESTIONS];


/* Resopnse buffer */
static uint8 dns_resp_buf[256];

/**
 * Parse all labels starting at data
 * @return new data pointer on success or NULL on error
 */
static char * ICACHE_FLASH_ATTR
dns_parse_labels(char *data, uint16 len, struct question *q)
{
        uint8  l_idx = 0;
        uint8  n_idx = 0;
        uint8  cur_len;

        do {
                /* Read and check label len */
                cur_len = *data++;
                if(cur_len > len) return NULL; //TODO: handle
                if(cur_len+n_idx > MAX_NAME_LEN) return NULL; //TODO: handle
                if(cur_len < 0) return NULL; //TODO: handle
                if(!cur_len) return data;

                /* Read label */
                q->label[l_idx] = q->name+n_idx;
                for(int i = 0; i < cur_len; ++i) {
                        q->name[n_idx++] = *data++;
                }

                l_idx++;
        }while(!cur_len);
}

static void ICACHE_FLASH_ATTR
dns_parse_questions(char *data, uint16 len)
{
        uint16 count;
        uint8  q_idx = 0;
        uint8  l_idx = 0;
        uint8  n_idx = 0;
        char   *ret;

        count = qdcount > MAX_QUESTIONS ? MAX_QUESTIONS : qdcount;

        if(len <= 0) return; //TODO: handle

        /* Parse each question record */
        while(q_idx < count) {

                ret = dns_parse_labels(data, len, &questions[q_idx]);
                if(!ret) return; //TODO: handle
                len -= ret-data;
                data=ret;

                if(len < 4) return; //TODO; handle
                questions[q_idx].type  = ntohs( data[0] );
                questions[q_idx].class = ntohs( data[2] );
                data += 4;

                q_idx++;
        }
}

void ICACHE_FLASH_ATTR
dns_parse(char *data, uint16 len)
{
        char *dptr = data;

        if(len < 2) return; // TODO: handle

        /* Copy id */
        id[0] = *dptr++;
        id[1] = *dptr++;

        /* Copy header */
        header[0] = *dptr++;
        header[1] = *dptr++;

        /* Read counts */
        qdcount = ntohs( (uint16) dptr[1] );
        ancount = ntohs( (uint16) dptr[3] );
        nscount = ntohs( (uint16) dptr[5] );
        arcount = ntohs( (uint16) dptr[7] );
        dptr += 8;

        dns_parse_questions(dptr, len-(dptr-data));
}
