/*
 * SYBAU-CORE C API.
 *
 * One core per process. All functions are thread-safe and must not be
 * called from inside a callback. Strings are NUL-terminated UTF-8.
 */
#ifndef SYBAU_H
#define SYBAU_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SYBAU_OK 0
#define SYBAU_ERR_INVALID_ARGUMENT 1
#define SYBAU_ERR_ALREADY_RUNNING 2
#define SYBAU_ERR_START_FAILED 3
#define SYBAU_ERR_NOT_RUNNING 4
#define SYBAU_ERR_PANIC 5

/* Receives events as JSON: {"method":"log"|"stats","params":{...}}.
 * `json` is only valid during the call. Invoked from core threads. */
typedef void (*sybau_event_callback)(void *user, const char *json);

/* Must exclude socket `fd` from the VPN (Android VpnService.protect)
 * and return non-zero on success. Invoked from core threads. */
typedef int32_t (*sybau_protect_callback)(void *user, int64_t fd);

/* Version string, e.g. "0.1.0". Static; do not free. */
const char *sybau_version(void);

/* Starts the core with a JSON config. On failure a message is stored in
 * *error_out (if not NULL); release it with sybau_free_string. */
int32_t sybau_start(const char *config_json, char **error_out);

/* Stops the core and closes every connection. */
int32_t sybau_stop(void);

/* Executes one control request, e.g.
 *   {"id":1,"method":"stats.get","params":{}}
 * and returns the JSON response; release it with sybau_free_string.
 * Same methods as the control channel of sybau.exe, except *.subscribe:
 * events arrive through the event callback instead. */
char *sybau_call(const char *request_json);

/* Sets (or clears, with NULL) the event callback. */
void sybau_set_event_callback(sybau_event_callback callback, void *user);

/* Sets (or clears, with NULL) the protect callback. Call before sybau_start. */
void sybau_set_protect_callback(sybau_protect_callback callback, void *user);

/* Releases a string returned by this library. */
void sybau_free_string(char *s);

#ifdef __cplusplus
}
#endif

#endif /* SYBAU_H */
