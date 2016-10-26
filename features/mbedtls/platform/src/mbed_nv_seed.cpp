/* mbed Microcontroller Library
 * Copyright (c) 2016 ARM Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "mbedtls/config.h"
#include "mbedtls/platform.h"

#if defined(MBEDTLS_ENTROPY_NV_SEED)

#if !defined(MBEDTLS_ENTROPY_NV_SEED_CFSTORE_KEY)
#define MBEDTLS_ENTROPY_NV_SEED_CFSTORE_KEY "NV_SEED"
#endif

#include "cfstore.h"

#include <stdint.h>

extern "C" {

int mbedtls_nv_seed_read(unsigned char *buf, size_t buf_len) {
    int32_t ret = CFSTORE_ERROR_GENERAL;
    size_t val_len = 0;
    cfstore::Cfstore cfstore = cfstore::Cfstore();
    cfstore::CfstoreKey *cfkey = NULL;
    cfstore::cfstore_fmode_t flags;

    memset(&flags, 0x00, sizeof(flags));
    flags.read = 1;

    ret = cfstore.initialize();
    if (ret < CFSTORE_OK)
        goto exit;

    cfkey = cfstore.open(MBEDTLS_ENTROPY_NV_SEED_CFSTORE_KEY, flags);
    if (!cfkey) {
        ret = CFSTORE_ERROR_GENERAL;
        goto uninitialize;
    }

    ret = cfkey->get_value_len(&val_len);
    if (ret < CFSTORE_OK)
        goto free;
    else if (val_len != buf_len) {
        ret = CFSTORE_ERROR_GENERAL;
        goto free;
    }

    ret = cfkey->read((void *)buf, &buf_len);
    if (ret < CFSTORE_OK)
        goto free;
    else if (val_len != buf_len) {
        ret = CFSTORE_ERROR_GENERAL;
        goto free;
    }

    ret = CFSTORE_OK;

free:
    if (cfkey->close() < CFSTORE_OK)
        ret = CFSTORE_ERROR_GENERAL;
    delete cfkey;

uninitialize:
    cfstore.uninitialize();

exit:
    return (ret == CFSTORE_OK) ? (int)buf_len : -1;
}

int mbedtls_nv_seed_write(unsigned char *buf, size_t buf_len) {
    int32_t ret = CFSTORE_ERROR_GENERAL;
    size_t val_len = buf_len;
    cfstore::Cfstore cfstore = cfstore::Cfstore();
    cfstore::CfstoreKey *cfkey = NULL;
    cfstore::cfstore_fmode_t flags;

    memset(&flags, 0x00, sizeof(flags));
    flags.write = 1;

    ret = cfstore.initialize();
    if (ret < CFSTORE_OK)
        goto exit;

    cfkey = cfstore.open(MBEDTLS_ENTROPY_NV_SEED_CFSTORE_KEY, flags);
    if (!cfkey) {
        ret = CFSTORE_ERROR_GENERAL;
        goto uninitialize;
    }

    ret = cfkey->write((const char *)buf, &buf_len);
    if (ret < CFSTORE_OK)
        goto free;
    else if (buf_len != val_len) {
        ret = CFSTORE_ERROR_GENERAL;
        goto free;
    }

    ret = cfstore.flush();
    if (ret < CFSTORE_OK)
        goto free;

    ret = CFSTORE_OK;

free:
    if (cfkey->close() < CFSTORE_OK)
        ret = CFSTORE_ERROR_GENERAL;
    delete cfkey;

uninitialize:
    cfstore.uninitialize();

exit:
    return (ret == CFSTORE_OK) ? (int)buf_len : -1;
}

}

#endif /* MBEDTLS_ENTROPY_NV_SEED */
