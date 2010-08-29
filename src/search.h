#ifndef WS_H_SEARCH
#define WS_H_SEARCH

#include <obstack.h>
#include <stddef.h>
#include <website.h>

typedef struct ws_match_item_s {
    size_t result;
    struct ws_match_item_s *next;
    char item[];
} ws_match_item_t;

typedef struct ws_match_box_s {
    struct obstack pieces;
    int hash_size;
    ws_match_item_t *first;
    ws_match_item_t *last;
    ws_match_item_t **hashed;
} ws_match_box_t;

typedef enum {
    WS_F_EXACT = 1,
    WS_F_PREFIX = 2,
} ws_fuzzy_flags;

typedef struct ws_fuzzy_item_s {
    int flags;
    int len;
    size_t exact_result;
    size_t prefix_result;
    struct ws_fuzzy_item_s *next;
    char item[];
} ws_fuzzy_item_t;

typedef struct ws_fuzzy_box_s {
    struct obstack pieces;
    int hash_size;
    ws_fuzzy_item_t **hashed;
    int *sizes;
    int nsizes;
    int maxlen;
    ws_fuzzy_item_t *first;
    ws_fuzzy_item_t *last;
} ws_fuzzy_box_t;

#endif // WS_H_SEARCH
