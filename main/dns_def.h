#ifndef __DNS_DEF_H_
#define __DNS_DEF_H_

#include "os_type.h"

#define MAX_QUESTIONS 4
#define MAX_NAME_LABEL 6
#define MAX_NAME_LEN 255
#define MAX_QUESTION_LEN MAX_NAME_LEN+4

struct question {
        char   name[255+MAX_NAME_LABEL];  // Respect lenth bytes
        char   *label[MAX_NAME_LABEL];
        uint16 type;
        uint16 class;
};

#endif // __DNS_DEF_H_
