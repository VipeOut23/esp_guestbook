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
#define IS_REPLY   !(header[0] & 0b00000001)
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


static uint8 dns_resp_buf[MAX_RESPONSE_SIZE];

enum dns_error dns_error;


/**
 * Parse all labels starting at data and write to question
 * @param data data to start reading from
 * @param len bytes available
 * @param q the question to be filled with labels
 * @return new data pointer on success or NULL on error
 */
static char * ICACHE_FLASH_ATTR
dns_parse_labels(char *data, uint16 len, struct question *q)
{
        uint8  l_idx = 0;
        uint8  n_idx = 0;
        uint8  cur_len;

        q->n_label = 0;

        if(len < 1)
        { dns_error = DNSE_PACKET_TOO_SMALL; return NULL; }

        for(;;) {
                /* Read and check label len */
                cur_len = *data++;
                if(cur_len > len)
                { dns_error = DNSE_LABEL_LEN_OVERFLOW; return NULL; }
                if(cur_len+n_idx > MAX_NAME_LEN)
                { dns_error = DNSE_NAME_LEN_OVERFLOW;  return NULL; }
                if(cur_len == 0) return data;

                /* Read label */
                q->labels[l_idx++] = q->name+n_idx;
                q->n_label++;
                while(cur_len--) {
                        q->name[n_idx++] = *data++;
                }
                q->name[n_idx++] = '\0';
        }
}

/**
 * Parse all question records
 * @param data data to start reading from
 * @param len bytes available
 */
static bool ICACHE_FLASH_ATTR
dns_parse_questions(char *data, uint16 len)
{
        uint16 count;
        uint8  q_idx = 0;
        char   *ret;

        count = qdcount > MAX_QUESTIONS ? MAX_QUESTIONS : qdcount;

        /* Parse each question record */
        while(q_idx < count) {

                ret = dns_parse_labels(data, len, &questions[q_idx]);
                if(!ret) return true;
                len -= ret-data;
                data=ret;

                if(len < 4)
                { dns_error = DNSE_PACKET_TOO_SMALL ; return true; }
                questions[q_idx].type  = ntohs( data[0] );
                questions[q_idx].class = ntohs( data[2] );
                data += 4;

                q_idx++;
        }
}

bool ICACHE_FLASH_ATTR
dns_check_header()
{
        bool ret = false;

        if( IS_TRUNC || IS_NOTIFY || IS_STATUS || IS_UPDATE ) {
                dns_error = DNSE_UNIMPLEMENTED;
                ret = true;
        }
        if( IS_REPLY ) {
                dns_error = DNSE_ERROR;
                ret = true;
        }

        return ret;
}

void ICACHE_FLASH_ATTR
dns_dump()
{
        os_printf("STATUS: %s\n", dns_errstr());
        os_printf("ID:      %02X:%02X\n", id[0], id[1]);
        os_printf("QDCOUNT: %d\n", qdcount);
        os_printf("ANCOUNT: %d\n", ancount);
        os_printf("NSCOUNT: %d\n", nscount);
        os_printf("ARCOUNT: %d\n", arcount);
        os_printf("----Questions----\n");

        for(int i = 0; i < qdcount; ++i) {
                for(int l = 0; l < questions[i].n_label; ++l) {
                        os_printf("  %s\n", questions[i].labels[l]);
                }
                os_printf("    TYPE:  %d\n", questions[i].type);
                os_printf("    CLASS: %d\n", questions[i].class);
        }

        os_printf("-----------------\n");
}

char* ICACHE_FLASH_ATTR
dns_errstr()
{
        switch(dns_error) {
        case DNSE_OK:
                return "OK";
        case DNSE_ERROR:
                return "ERROR";
        case DNSE_PACKET_TOO_SMALL:
                return "packet too small, to proceed parsing";
        case DNSE_LABEL_LEN_OVERFLOW:
                return "length of label is too long";
        case DNSE_NAME_LEN_OVERFLOW:
                return "length of name is too long";
        case DNSE_UNIMPLEMENTED:
                return "requested feature, but it's not implemented";
        }
}

/**
 * Parse data as DNS packet
 * @param data the packet data
 * @param len size of data
 * @return false = success ; true = error (@see dns_errstr())
 */
bool ICACHE_FLASH_ATTR
dns_parse(char *data, uint16 len)
{
        bool err;

        char *dptr = data;

        dns_error = DNSE_OK;

        if(len < 12)
        { dns_error = DNSE_PACKET_TOO_SMALL; return true; }

        /* Copy id */
        id[0] = *dptr++;
        id[1] = *dptr++;

        /* Copy header */
        header[0] = *dptr++;
        header[1] = *dptr++;

        /* Read counts */
        // TODO: do this properly
        qdcount = dptr[1];
        qdcount |= dptr[0]<<8;
        ancount = dptr[3];
        ancount |= dptr[2]<<8;
        nscount = dptr[5];
        nscount |= dptr[4]<<8;
        arcount = dptr[7];
        arcount |= dptr[6]<<8;
        dptr += 8;

        err = dns_check_header();
        if(err) return err;

        err = dns_parse_questions(dptr, len-(dptr-data));

        return err;
}
