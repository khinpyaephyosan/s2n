/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#include <s2n.h>

#include "error/s2n_errno.h"

#include "tls/s2n_connection.h"
#include "tls/s2n_tls.h"

#include "stuffer/s2n_stuffer.h"

#include "utils/s2n_safety.h"

const uint8_t hello_retry_req_random[] = {
    0xCF ,0x21 ,0xAD ,0x74 ,0xE5 ,0x9A ,0x61 ,0x11 ,0xBE ,0x1D ,0x8C ,0x02 ,0x1E ,0x65 ,0xB8 ,0x91,
    0xC2 ,0xA2 ,0x11 ,0x16 ,0x7A ,0xBB ,0x8C ,0x5E ,0x07 ,0x9E ,0x09 ,0xE2 ,0xC8 ,0xA8 ,0x33 ,0x9C
};

#define S2N_TLS_COMPRESSION_METHOD_NULL 0
int s2n_server_hello_retry_send(struct s2n_connection *conn)
{
    struct s2n_stuffer *out = &conn->handshake.io;
    struct s2n_stuffer server_random = {0};
    struct s2n_blob b, r;
    uint8_t protocol_version[S2N_TLS_PROTOCOL_VERSION_LEN];

    b.data = conn->secure.server_random;
    b.size = S2N_TLS_RANDOM_DATA_LEN;

    /* Create the server random data */
    GUARD(s2n_stuffer_init(&server_random, &b));

    /* Use the random value specified in RFC8446 */
    r.data = s2n_stuffer_raw_write(&server_random, S2N_TLS_RANDOM_DATA_LEN);
    /*r.size = S2N_TLS_RANDOM_DATA_LEN;*/
    notnull_check(r.data);
    memcpy(r.data, hello_retry_req_random, S2N_TLS_RANDOM_DATA_LEN);

    protocol_version[0] = (uint8_t)(conn->actual_protocol_version / 10);
    protocol_version[1] = (uint8_t)(conn->actual_protocol_version % 10);


    GUARD(s2n_stuffer_write_bytes(out, protocol_version, S2N_TLS_PROTOCOL_VERSION_LEN));
    GUARD(s2n_stuffer_write_bytes(out, conn->secure.server_random, S2N_TLS_RANDOM_DATA_LEN));
    GUARD(s2n_stuffer_write_uint8(out, conn->session_id_len));
    GUARD(s2n_stuffer_write_bytes(out, conn->session_id, conn->session_id_len));
    GUARD(s2n_stuffer_write_bytes(out, conn->secure.cipher_suite->iana_value, S2N_TLS_CIPHER_SUITE_LEN));
    GUARD(s2n_stuffer_write_uint8(out, S2N_TLS_COMPRESSION_METHOD_NULL));

    GUARD(s2n_server_extensions_send(conn, out));

    conn->actual_protocol_version_established = 1;

    return 0;
}

int s2n_server_hello_retry_recv(struct s2n_connection *conn)
{
    /* Verify server hello retry */
    S2N_ERROR(S2N_ERR_UNIMPLEMENTED);

    /* Parse server hello */
    /*GUARD(s2n_parse_client_hello_retry(conn));
    GUARD(s2n_populate_client_hello_extensions(&conn->client_hello));*/

}
