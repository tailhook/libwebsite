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

#endif // WS_H_SEARCH
