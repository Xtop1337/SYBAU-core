/* Smoke test of the C API: start, call, events, stop. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#define sleep_ms(ms) Sleep(ms)
#else
#include <unistd.h>
#define sleep_ms(ms) usleep((ms) * 1000)
#endif

#include "sybau.h"

static volatile int events = 0;

static void on_event(void *user, const char *json) {
    (void)user;
    if (strstr(json, "\"method\"")) events++;
}

#define CHECK(cond, msg)                         \
    do {                                         \
        if (!(cond)) {                           \
            fprintf(stderr, "FAIL: %s\n", msg);  \
            return 1;                            \
        }                                        \
    } while (0)

int main(int argc, char **argv) {
    const char *port = argc > 1 ? argv[1] : "20811";
    char config[512];
    char *err = NULL;

    printf("version %s\n", sybau_version());
    CHECK(strlen(sybau_version()) > 0, "version is empty");

    CHECK(sybau_stop() == SYBAU_ERR_NOT_RUNNING, "stop before start");
    CHECK(sybau_start(NULL, &err) == SYBAU_ERR_INVALID_ARGUMENT && err, "null config");
    sybau_free_string(err);
    err = NULL;
    CHECK(sybau_start("{\"route\":{\"final\":\"missing\"}}", &err) == SYBAU_ERR_START_FAILED && err, "bad config");
    printf("expected error: %s\n", err);
    sybau_free_string(err);
    err = NULL;

    sybau_set_event_callback(on_event, NULL);
    snprintf(config, sizeof config,
             "{\"log\":{\"level\":\"info\"},\"inbounds\":[{\"type\":\"mixed\",\"port\":%s}]}", port);
    CHECK(sybau_start(config, &err) == SYBAU_OK, err ? err : "start failed");
    CHECK(sybau_start(config, NULL) == SYBAU_ERR_ALREADY_RUNNING, "second start");

    char *resp = sybau_call("{\"id\":7,\"method\":\"core.version\"}");
    CHECK(resp && strstr(resp, "SYBAU-CORE") && strstr(resp, "\"id\":7"), "core.version");
    sybau_free_string(resp);
    resp = sybau_call("{\"id\":8,\"method\":\"nope\"}");
    CHECK(resp && strstr(resp, "\"error\""), "unknown method");
    sybau_free_string(resp);
    resp = sybau_call("not json");
    CHECK(resp && strstr(resp, "\"error\""), "malformed request");
    sybau_free_string(resp);

    sleep_ms(1500);
    CHECK(events > 0, "no events delivered");
    sybau_set_event_callback(NULL, NULL);

    CHECK(sybau_stop() == SYBAU_OK, "stop");
    CHECK(sybau_stop() == SYBAU_ERR_NOT_RUNNING, "second stop");
    CHECK(sybau_start(config, &err) == SYBAU_OK, err ? err : "restart failed");
    CHECK(sybau_stop() == SYBAU_OK, "stop after restart");
    printf("C API OK (%d events)\n", events);
    return 0;
}
