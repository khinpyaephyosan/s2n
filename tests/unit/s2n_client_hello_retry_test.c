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

#include "s2n_test.h"

#include "testlib/s2n_testlib.h"

#include <s2n.h>

#include "error/s2n_errno.h"

#include "tls/s2n_tls.h"
#include "tls/s2n_tls13.h"

#include "utils/s2n_blob.h"
#include "utils/s2n_safety.h"

#define LENGTH_TO_RANDOM_DATA   S2N_TLS_PROTOCOL_VERSION_LEN
#define LENGTH_TO_SESSION_ID    S2N_TLS_PROTOCOL_VERSION_LEN + S2N_TLS_RANDOM_DATA_LEN
#define LENGTH_TO_EXTENSTIONS   S2N_TLS_PROTOCOL_VERSION_LEN + S2N_TLS_RANDOM_DATA_LEN + SESSION_ID_SIZE + 32 + S2N_TLS_CIPHER_SUITE_LEN + COMPRESSION_METHOD_SIZE

const uint8_t hello_retry_req_random[] = {
    0xCF ,0x21 ,0xAD ,0x74 ,0xE5 ,0x9A ,0x61 ,0x11 ,0xBE ,0x1D ,0x8C ,0x02 ,0x1E ,0x65 ,0xB8 ,0x91,
     0xC2 ,0xA2 ,0x11 ,0x16 ,0x7A ,0xBB ,0x8C ,0x5E ,0x07 ,0x9E ,0x09 ,0xE2 ,0xC8 ,0xA8 ,0x33 ,0x9C
};

const uint8_t SESSION_ID_SIZE = 1;
const uint8_t COMPRESSION_METHOD_SIZE = 1;

int main(int argc, char **argv)
{
    BEGIN_TEST();

    EXPECT_SUCCESS(s2n_enable_tls13());

    /* Test basic Server Hello Retry Send */
    {
        struct s2n_config *config;
        EXPECT_NOT_NULL(config = s2n_config_new());

        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

        /* Setup connection to respond to a TLS13 Client Hello with a single extension */
        conn->client_protocol_version = S2N_TLS13;
        conn->server_protocol_version = S2N_TLS13;
        conn->actual_protocol_version = S2N_TLS13;
        memcpy_check(conn->application_protocol, "TESTALPN", 8);

        struct s2n_stuffer *hello_stuffer = &conn->handshake.io;

        /* Test s2n_server_hello_retry_send */
        EXPECT_SUCCESS(s2n_server_hello_retry_send(conn));

        /* Verify the random value matches the value specified in the RFC */
        {
            EXPECT_SUCCESS(s2n_stuffer_skip_read(hello_stuffer, LENGTH_TO_RANDOM_DATA));

            uint8_t server_random[S2N_TLS_RANDOM_DATA_LEN];
            EXPECT_SUCCESS(s2n_stuffer_read_bytes(hello_stuffer, server_random, S2N_TLS_RANDOM_DATA_LEN));

            /* RFC8446 section 4.1.3 provides a special value that the HelloRetryRequest message should contain */
            EXPECT_BYTEARRAY_EQUAL(hello_retry_req_random, server_random, S2N_TLS_RANDOM_DATA_LEN);
        }

        /* Verify that the extensions returned by the server are expected */
        {
            EXPECT_SUCCESS(s2n_stuffer_skip_read(hello_stuffer, SESSION_ID_SIZE + conn->session_id_len + S2N_TLS_CIPHER_SUITE_LEN + COMPRESSION_METHOD_SIZE));

            uint16_t extensions_size;
            GUARD(s2n_stuffer_read_uint16(hello_stuffer, &extensions_size));
            EXPECT_EQUAL(extensions_size, s2n_stuffer_data_available(hello_stuffer));

            uint8_t found_alpn_extension = 0;
            uint8_t found_supported_versions_extension = 0;
            uint8_t found_unexpected_extension = 0;
            while (s2n_stuffer_data_available(hello_stuffer)) {
                uint16_t extension_type;
                uint16_t extension_size;
                EXPECT_SUCCESS(s2n_stuffer_read_uint16(hello_stuffer, &extension_type));
                EXPECT_SUCCESS(s2n_stuffer_read_uint16(hello_stuffer, &extension_size));

                /* 
                 * RFC8446 section 4.1.4 specifies the retry MUST contain supported_versions,
                 * SHOULD contain other extensions sent in the client hello, and
                 * MUST NOT contain extensions that were not offerred by the client.
                 */
                switch (extension_type) {
                    case TLS_EXTENSION_SUPPORTED_VERSIONS:
                        found_supported_versions_extension = 1;
                        break;
                    case TLS_EXTENSION_ALPN:
                        found_alpn_extension = 1;
                        break;
                    default:
                        found_unexpected_extension = 1;
                        break;
                }

                EXPECT_SUCCESS(s2n_stuffer_skip_read(hello_stuffer, extension_size));
            }

            EXPECT_EQUAL(found_supported_versions_extension, 1);
            EXPECT_EQUAL(found_alpn_extension, 1);
            EXPECT_EQUAL(found_unexpected_extension, 0);
        }

        EXPECT_SUCCESS(s2n_config_free(config));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Test extension inclusion in Hello Retry response */
    {
        struct s2n_config *config;
        EXPECT_NOT_NULL(config = s2n_config_new());

        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
        conn->client_protocol_version = S2N_TLS13;
        conn->server_protocol_version = S2N_TLS13;
        conn->actual_protocol_version = S2N_TLS13;

        struct s2n_stuffer *hello_stuffer = &conn->handshake.io;

        /* Test s2n_server_hello_retry_send */
        memcpy_check(conn->application_protocol, "TESTALPN", 8);
        EXPECT_SUCCESS(s2n_server_hello_retry_send(conn));

        /* Verify that the extensions returned by the server are expected */
        {
            EXPECT_SUCCESS(s2n_stuffer_skip_read(hello_stuffer, LENGTH_TO_SESSION_ID + SESSION_ID_SIZE + conn->session_id_len + S2N_TLS_CIPHER_SUITE_LEN + COMPRESSION_METHOD_SIZE));

            uint16_t extensions_size;
            GUARD(s2n_stuffer_read_uint16(hello_stuffer, &extensions_size));
            EXPECT_EQUAL(extensions_size, s2n_stuffer_data_available(hello_stuffer));

            uint8_t found_key_share_extension = 0;
            uint8_t found_supported_versions_extension = 0;
            uint8_t found_unexpected_extension = 0;
            while (s2n_stuffer_data_available(hello_stuffer)) {
                uint16_t extension_type;
                uint16_t extension_size;
                EXPECT_SUCCESS(s2n_stuffer_read_uint16(hello_stuffer, &extension_type));
                EXPECT_SUCCESS(s2n_stuffer_read_uint16(hello_stuffer, &extension_size));

                /* 
                 * RFC8446 section 4.1.4 specifies the retry MUST contain supported_versions and 
                 * MUST NOT contain extensions that were not offerred by the client.
                 */
                switch (extension_type) {
                    case TLS_EXTENSION_SUPPORTED_VERSIONS:
                        printf("XXX Found supported version\n");
                        found_supported_versions_extension = 1;
                        break;
                    case TLS_EXTENSION_ALPN:
                        printf("XXX Found ALPN\n");
                        found_key_share_extension = 1;
                        break;
                    default:
                        found_unexpected_extension = 1;
                        break;
                }

                EXPECT_SUCCESS(s2n_stuffer_skip_read(hello_stuffer, extension_size));
            }

            EXPECT_EQUAL(found_supported_versions_extension, 1);
            EXPECT_EQUAL(found_key_share_extension, 1);
            EXPECT_EQUAL(found_unexpected_extension, 0);
        }

        EXPECT_SUCCESS(s2n_config_free(config));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    EXPECT_SUCCESS(s2n_disable_tls13());

    END_TEST();
}
