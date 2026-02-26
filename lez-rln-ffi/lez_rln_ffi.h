#ifndef LEZ_RLN_FFI_H
#define LEZ_RLN_FFI_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef enum RlnFfiError {
  RLN_FFI_ERROR_SUCCESS = 0,
  RLN_FFI_ERROR_NULL_POINTER = 1,
  RLN_FFI_ERROR_DATA_TOO_SHORT = 2,
} RlnFfiError;

/**
 * Parse tree-main account data and write valid roots into `out_roots`.
 *
 * `out_roots`: caller buffer, at least 160 bytes (5 x 32).
 * `out_count`: set to number of valid roots written (1..=5).
 *
 * Slot 0 = current root. Slots 1..N = non-zero history entries.
 */
enum RlnFfiError rln_ffi_get_valid_roots(const uint8_t *data_ptr,
                                         uintptr_t data_len,
                                         uint8_t *out_roots,
                                         uint32_t *out_count);

#endif  /* LEZ_RLN_FFI_H */
