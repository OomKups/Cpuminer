#include "miner.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "sha3/sph_groestl.h"
#include "kupyna/kupyna512.h"

void mirinae_hash(void *output, const void *input, int height, const void *seed)
{	
	unsigned char _ALIGN(128) hash[64] = { 0 };
	unsigned char _ALIGN(128) offset[64] = { 0 };
	const int window = 4096;
	const int aperture = 32;
	int64_t n = 0;

	sph_groestl512_context ctx_groestl;
	struct kupyna512_ctx_t ctx_kupyna;

	kupyna512_init(&ctx_kupyna);
	kupyna512_update(&ctx_kupyna, seed, 32);
	kupyna512_final(&ctx_kupyna, offset);
	memcpy(&n, offset, 8);

	sph_groestl512_init(&ctx_groestl);
	sph_groestl512(&ctx_groestl, input, 80);
	sph_groestl512_close(&ctx_groestl, hash);

	unsigned int h_loop = hash[0];
	for (int i = 0; i < (((n % height) + (height + 1)) % window); i++) {
		for (int j = 0; j < (h_loop % aperture); j++) {
			kupyna512_init(&ctx_kupyna);
			kupyna512_update(&ctx_kupyna, hash, 64);
			kupyna512_final(&ctx_kupyna, hash);
		}

		h_loop = hash[0];
	}

	sph_groestl512_init(&ctx_groestl);
	sph_groestl512(&ctx_groestl, hash, 64);
	sph_groestl512_close(&ctx_groestl, hash);

	memcpy(output, hash, 32);
}

int scanhash_mirinae(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{
	uint32_t _ALIGN(128) hash[8];
	uint32_t _ALIGN(128) endiandata[20];
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;

	const uint32_t Htarg = ptarget[7];
	const uint32_t first_nonce = pdata[19];
	uint32_t nonce = first_nonce;

	for (int k=0; k < 19; k++)
		be32enc(&endiandata[k], pdata[k]);

	do {
		be32enc(&endiandata[19], nonce);
		mirinae_hash(hash, endiandata, work->height, work->prevhash);

		if (hash[7] <= Htarg && fulltest(hash, ptarget)) {
			work_set_target_ratio(work, hash);
			pdata[19] = nonce;
			*hashes_done = pdata[19] - first_nonce;
			return 1;
		}
		nonce++;

	} while (nonce < max_nonce && !work_restart[thr_id].restart);

	pdata[19] = nonce;
	*hashes_done = pdata[19] - first_nonce + 1;
	return 0;
}
