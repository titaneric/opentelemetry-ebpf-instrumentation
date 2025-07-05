// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

#include <bpfcore/utils.h>

#include <pid/pid_helpers.h>

#include <common/http_types.h>

// TODO: enums
#define K_TCP_MAX_LEN 256
#define K_TCP_RES_LEN 128

#define PATH_MAX_LEN 100
#define METHOD_MAX_LEN 7 // Longest method: OPTIONS
#define REMOTE_ADDR_MAX_LEN                                                                        \
    50 // We need 48: 39(ip v6 max) + 1(: separator) + 7(port length max value 65535) + 1(null terminator)
#define HOST_LEN 64 // can be a fully qualified DNS name
#define TRACEPARENT_LEN 55
#define SQL_MAX_LEN 500
#define KAFKA_MAX_LEN 256
#define REDIS_MAX_LEN 256
#define MAX_TOPIC_NAME_LEN 64
#define HOST_MAX_LEN 100
#define SCHEME_MAX_LEN 10

volatile const u32 mysql_buffer_size = 0;

enum {
    k_mysql_query_max = 8192,
    k_mysql_query_max_mask = k_mysql_query_max - 1,
    k_mysql_error_message_max = 512,
    k_mysql_error_message_max_mask = k_mysql_error_message_max - 1
};

// Trace of an HTTP call invocation. It is instantiated by the return uprobe and forwarded to the
// user space through the events ringbuffer.
// TODO(matt): fix naming
typedef struct http_request_trace_t {
    u8 type; // Must be first
    u8 _pad0[1];
    u16 status;
    unsigned char method[METHOD_MAX_LEN];
    unsigned char scheme[SCHEME_MAX_LEN];
    u8 _pad1[11];
    u64 go_start_monotime_ns;
    u64 start_monotime_ns;
    u64 end_monotime_ns;
    s64 content_length;
    s64 response_length;
    unsigned char path[PATH_MAX_LEN];
    unsigned char host[HOST_MAX_LEN];
    tp_info_t tp;
    connection_info_t conn;
    pid_info pid;
} http_request_trace;

// TODO(matt): fix naming
typedef struct sql_request_trace_t {
    u8 type; // Must be first
    u8 _pad[1];
    u16 status;
    pid_info pid;
    u64 start_monotime_ns;
    u64 end_monotime_ns;
    tp_info_t tp;
    connection_info_t conn;
    unsigned char sql[SQL_MAX_LEN];
} sql_request_trace;

typedef struct kafka_client_req {
    u8 type; // Must be first
    u8 _pad[7];
    u64 start_monotime_ns;
    u64 end_monotime_ns;
    unsigned char buf[KAFKA_MAX_LEN];
    connection_info_t conn;
    pid_info pid;
} kafka_client_req_t;

typedef struct kafka_go_req {
    u8 type; // Must be first
    u8 op;
    u8 _pad0[2];
    pid_info pid;
    connection_info_t conn;
    u8 _pad1[4];
    tp_info_t tp;
    u64 start_monotime_ns;
    u64 end_monotime_ns;
    unsigned char topic[MAX_TOPIC_NAME_LEN];
} kafka_go_req_t;

typedef struct redis_client_req {
    u8 type; // Must be first
    u8 err;
    u8 _pad[6];
    u64 start_monotime_ns;
    u64 end_monotime_ns;
    pid_info pid;
    unsigned char buf[REDIS_MAX_LEN];
    connection_info_t conn;
    tp_info_t tp;
} redis_client_req_t;

// Here we track unknown TCP requests that are not HTTP, HTTP2 or gRPC
typedef struct tcp_req {
    u8 flags; // Must be fist we use it to tell what kind of packet we have on the ring buffer
    u8 ssl;
    u8 direction;
    u8 has_large_buffers;
    enum protocol_type protocol_type;
    u8 _pad1[3];
    connection_info_t conn_info;
    u32 len;
    u64 start_monotime_ns;
    u64 end_monotime_ns;
    u64 extra_id;
    u32 req_len;
    u32 resp_len;
    u8 _pad2[4];
    unsigned char buf[K_TCP_MAX_LEN];
    unsigned char rbuf[K_TCP_RES_LEN];
    // we need this to filter traces from unsolicited processes that share the executable
    // with other instrumented processes
    pid_info pid;
    tp_info_t tp;
} tcp_req_t;

typedef struct tcp_large_buffer {
    u8 type; // Must be first
    u8 direction;
    u8 _pad[2];
    u32 len;
    tp_info_t tp;
    u8 buf[];
} tcp_large_buffer_t;
