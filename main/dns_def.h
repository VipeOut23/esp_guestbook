#ifndef __DNS_DEF_H_
#define __DNS_DEF_H_

#include "os_type.h"

#define MAX_QUESTIONS     4
#define MAX_NAME_LABEL    6
#define MAX_NAME_LEN      255
#define MAX_QUESTION_LEN  MAX_NAME_LEN+4
#define MAX_RESPONSE_SIZE 512  // Must be over 6 (for responses without records)
#define MAX_RDATA_LENGTH  255

/* Rcodes */
#define    RC_NoError  0
#define    RC_FormErr  1
#define    RC_ServFail 2
#define    RC_NXDomain 3
#define    RC_NotImp   4
#define    RC_Refused  5
#define    RC_YXDomain 6
#define    RC_YXRRSet  7
#define    RC_NXRRSet  8
#define    RC_NotAuth  9
#define    RC_NotZone  10
#define    RC_BADVERS  16
#define    RC_BADSIG   16
#define    RC_BADKEY   17
#define    RC_BADTIME  18
#define    RC_BADMODE  19
#define    RC_BADNAME  20
#define    RC_BADALG   21
#define    RC_BADTRUC  22


struct question {
        char   name[255+MAX_NAME_LABEL];  // Respect lenth bytes
        char   *labels[MAX_NAME_LABEL];
        uint8  n_label;
        uint16 type;
        uint16 class;
};

struct resource_record {
        char   name[255+MAX_NAME_LABEL];  // Respect lenth bytes
        uint16 type;
        uint16 class;
        uint32 ttl;
        uint16 rdlength;
        char   rdata[MAX_RDATA_LENGTH];
};

#endif // __DNS_DEF_H_
