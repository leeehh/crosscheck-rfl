// SPDX-License-Identifier: GPL-2.0

#include <crypto/skcipher.h>
#include <crypto/internal/skcipher.h>

/* `crypto_register_skcipher` (singular) is a static inline wrapping `crypto_register_skciphers`;
 * the ctx/reqtfm/ivsize/request_ctx/request_complete accessors are static inlines too. Wrap them so
 * Rust can call them (mirrors rust/helpers/scsi.c). Auto-exported via exports_helpers_generated.h. */
int rust_helper_crypto_register_skcipher(struct skcipher_alg *alg)
{
	return crypto_register_skcipher(alg);
}

void rust_helper_crypto_unregister_skcipher(struct skcipher_alg *alg)
{
	crypto_unregister_skcipher(alg);
}

void *rust_helper_crypto_skcipher_ctx(struct crypto_skcipher *tfm)
{
	return crypto_skcipher_ctx(tfm);
}

void *rust_helper_skcipher_request_ctx(struct skcipher_request *req)
{
	return skcipher_request_ctx(req);
}

struct crypto_skcipher *rust_helper_crypto_skcipher_reqtfm(struct skcipher_request *req)
{
	return crypto_skcipher_reqtfm(req);
}

unsigned int rust_helper_crypto_skcipher_ivsize(struct crypto_skcipher *tfm)
{
	return crypto_skcipher_ivsize(tfm);
}

void rust_helper_skcipher_request_complete(struct skcipher_request *req, int err)
{
	skcipher_request_complete(req, err);
}

unsigned int rust_helper_crypto_skcipher_reqsize(struct crypto_skcipher *tfm)
{
	return crypto_skcipher_reqsize(tfm);
}
