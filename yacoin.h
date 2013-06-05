#ifndef __YACOIN_H__
#define __YACOIN_H__
/* 
include the constants and functions needed for YaCoin 

pulled out of the original scrypt-jane.c in ali1234's repository

*/


unsigned char GetNfactor(unsigned int nTimestamp)

int scanhash_scrypt_jane(int thr_id, uint32_t *pdata,
        const uint32_t *ptarget,
        uint32_t max_nonce, unsigned long *hashes_done)

#endif /* __YACOIN_H__ */
