/*
 * A data channel exchange between two driven peer connections over loopback, through the C
 * interface only: one peer on sockets of its own, the other on a shared UDP port (rtci_mux).
 * Signaling is in this process; candidates are trickled from the icecandidate events. Exits 0
 * when the answerer's echo of the offerer's message came back and every object was freed.
 *
 * Built and run by tests/c_loopback.rs against the static library.
 */
#include "rtci.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void die(const char *what, int32_t code) {
    char message[1024];
    rtci_last_error(message, sizeof message);
    fprintf(stderr, "%s failed: %d %s\n", what, code, message);
    exit(1);
}

/* Calls a method; the result string (free with rtci_string_free). */
static char *call(rtci_driven *d, const char *method, const char *params, const uint8_t *data,
                  size_t len) {
    char *out = NULL;
    int32_t code = rtci_driven_call(d, method, params, data, len, &out);
    if (code != RTCI_OK) {
        die(method, code);
    }
    return out;
}

static void call0(rtci_driven *d, const char *method, const char *params) {
    rtci_string_free(call(d, method, params, NULL, 0));
}

/* The integer after "key": in a compact JSON text, or -1. */
static long number(const char *json, const char *key) {
    char pattern[64];
    snprintf(pattern, sizeof pattern, "\"%s\":", key);
    const char *at = strstr(json, pattern);
    return at ? strtol(at + strlen(pattern), NULL, 10) : -1;
}

static int is_type(const char *json, const char *type) {
    char pattern[64];
    snprintf(pattern, sizeof pattern, "\"type\":\"%s\"", type);
    return strstr(json, pattern) != NULL;
}

/* Copies the JSON object after "key": into out (NUL-terminated); 0 when there is none. */
static int object(const char *json, const char *key, char *out, size_t cap) {
    char pattern[64];
    snprintf(pattern, sizeof pattern, "\"%s\":{", key);
    const char *start = strstr(json, pattern);
    if (!start) {
        return 0;
    }
    start += strlen(pattern) - 1;
    int depth = 0, in_string = 0;
    for (const char *p = start; *p; p++) {
        if (in_string) {
            if (*p == '\\' && p[1]) {
                p++;
            } else if (*p == '"') {
                in_string = 0;
            }
            continue;
        }
        if (*p == '"') {
            in_string = 1;
        } else if (*p == '{') {
            depth++;
        } else if (*p == '}' && --depth == 0) {
            size_t n = (size_t)(p - start + 1);
            if (n + 1 > cap) {
                return 0;
            }
            memcpy(out, start, n);
            out[n] = 0;
            return 1;
        }
    }
    return 0;
}

static uint8_t item[1 << 18];
static char header[1 << 16];

/* Takes the next item: its header in `header`, its payload at *data. 0 when none. */
static int next(rtci_driven *d, const uint8_t **data, size_t *data_len) {
    size_t json_len = 0;
    int32_t code = rtci_driven_next(d, item, sizeof item, &json_len, data_len);
    if (code == RTCI_EMPTY) {
        return 0;
    }
    if (code != RTCI_OK || json_len >= sizeof header) {
        die("rtci_driven_next", code);
    }
    memcpy(header, item, json_len);
    header[json_len] = 0;
    *data = item + json_len;
    return 1;
}

int main(void) {
    static const char message[] = "hello from C";
    if (rtci_abi_version() != RTCI_ABI_VERSION) {
        fprintf(stderr, "ABI %u, header %u\n", rtci_abi_version(), RTCI_ABI_VERSION);
        return 1;
    }
    printf("rtci-ffi %s\n", rtci_version());
    int32_t code;
    rtci_mux *mux = NULL;
    if ((code = rtci_mux_new("{\"udp\":\"127.0.0.1:0\"}", &mux)) != RTCI_OK) {
        die("rtci_mux_new", code);
    }
    const char *settings = "{\"interceptors\":\"minimal\"}";
    rtci_driven *peers[2] = {NULL, NULL};
    if ((code = rtci_driven_new(NULL, settings,
                               "{\"bindAddresses\":[\"127.0.0.1\"],\"includeLoopback\":true,"
                               "\"tcp\":false}",
                               NULL, &peers[0])) != RTCI_OK) {
        die("rtci_driven_new (offerer)", code);
    }
    if ((code = rtci_driven_new(NULL, settings, "{\"tcp\":false}", mux, &peers[1])) != RTCI_OK) {
        die("rtci_driven_new (answerer)", code);
    }

    char *created = call(peers[0], "createDataChannel", "{\"label\":\"loop\"}", NULL, 0);
    long channel = number(created, "channel");
    rtci_string_free(created);

    char *offer = call(peers[0], "createOffer", NULL, NULL, 0);
    call0(peers[0], "setLocalDescription", offer);
    call0(peers[1], "setRemoteDescription", offer);
    rtci_string_free(offer);
    char *answer = call(peers[1], "createAnswer", NULL, NULL, 0);
    call0(peers[1], "setLocalDescription", answer);
    call0(peers[0], "setRemoteDescription", answer);
    rtci_string_free(answer);

    int sent = 0, echoed = 0, done = 0;
    char candidate[4096], params[128];
    for (int round = 0; round < 400 && !done; round++) {
        for (int side = 0; side < 2 && !done; side++) {
            rtci_driven *self = peers[side], *other = peers[1 - side];
            code = rtci_driven_wait(self, 25);
            if (code < 0) {
                die("rtci_driven_wait", code);
            }
            const uint8_t *data;
            size_t len;
            while (next(self, &data, &len)) {
                if (is_type(header, "icecandidate") &&
                    object(header, "candidate", candidate, sizeof candidate)) {
                    char *out = NULL;
                    /* A candidate the description already carried may be refused: fine. */
                    if (rtci_driven_call(other, "addIceCandidate", candidate, NULL, 0, &out) ==
                        RTCI_OK) {
                        rtci_string_free(out);
                    }
                } else if (side == 0 && is_type(header, "open") && !sent) {
                    snprintf(params, sizeof params, "{\"channel\":%ld,\"isString\":true}",
                             channel);
                    rtci_string_free(call(self, "dataChannelSend", params,
                                         (const uint8_t *)message, strlen(message)));
                    sent = 1;
                    printf("offerer: channel open, sent \"%s\"\n", message);
                } else if (side == 1 && is_type(header, "message")) {
                    snprintf(params, sizeof params, "{\"channel\":%ld,\"isString\":true}",
                             number(header, "channel"));
                    rtci_string_free(call(self, "dataChannelSend", params, data, len));
                    echoed = 1;
                    printf("answerer: echoed %zu bytes\n", len);
                } else if (side == 0 && is_type(header, "message")) {
                    if (len != strlen(message) || memcmp(data, message, len) != 0) {
                        fprintf(stderr, "the echo differs: %.*s\n", (int)len, data);
                        return 1;
                    }
                    printf("offerer: the echo came back\n");
                    done = 1;
                } else if (is_type(header, "error")) {
                    fprintf(stderr, "side %d: %s\n", side, header);
                }
            }
        }
    }
    if (!done) {
        fprintf(stderr, "no echo (sent %d, echoed %d)\n", sent, echoed);
        return 1;
    }
    rtci_driven_free(peers[0]);
    rtci_driven_free(peers[1]);
    rtci_mux_free(mux);
    int64_t live = rtci_debug_live_objects();
    if (live != 0) {
        fprintf(stderr, "%lld objects left alive\n", (long long)live);
        return 1;
    }
    printf("ok\n");
    return 0;
}
