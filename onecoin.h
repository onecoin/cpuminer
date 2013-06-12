#ifndef __ONECOIN_H__
#define __ONECOIN_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned char GetNfactor(unsigned int nTimestamp);

int scanhash_onecoin(int thr_id, uint32_t *pdata,
        const uint32_t *ptarget,
        uint32_t max_nonce, unsigned long *hashes_done);

#endif /* __ONECOIN_H__ */

