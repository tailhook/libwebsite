#include <malloc.h>
#include <stddef.h>
#include <assert.h>
#include <strings.h>
#include <ctype.h>

#include "search.h"

#define TRUE 1
#define FALSE 0

#define obstack_chunk_alloc malloc
#define obstack_chunk_free free

void *ws_match_new() {
    ws_match_box_t *box = (ws_match_box_t*)malloc(sizeof(ws_match_box_t));
    if(!box) {
        return NULL;
    }
    obstack_init(&box->pieces);
    box->hash_size = 0;
    box->first = NULL;
    box->last = NULL;
    return box;
}

void ws_match_free(void *hint) {
    ws_match_box_t *box = hint;
    obstack_free(&box->pieces, NULL);
    free(box);
}

size_t ws_match_add(void *rbox, const char *value, size_t result) {
    ws_match_box_t *box = (ws_match_box_t*)rbox;
    assert(!box->hash_size);
    ws_match_item_t *t = box->first;
    while(t) {
        if(!strcmp(value, t->item)) {
            return t->result;
        }
        t = t->next;
    }
    ws_match_item_t *res = (ws_match_item_t*)obstack_alloc(&box->pieces,
        sizeof(ws_match_item_t)+strlen(value)+1);
    res->result = result;
    res->next = NULL;
    if(!box->first) {
        box->first = res;
    } else {
        box->last->next = res;
    }
    box->last = res;
    strcpy(res->item, value);
    return result;
}

size_t ws_match_iadd(void *rbox, const char *value, size_t result) {
    ws_match_box_t *box = (ws_match_box_t*)rbox;
    assert(!box->hash_size);
    ws_match_item_t *t = box->first;
    while(t) {
        if(!strcasecmp(value, t->item)) {
            return t->result;
        }
        t = t->next;
    }
    int vlen = strlen(value);
    ws_match_item_t *res = (ws_match_item_t*)obstack_alloc(&box->pieces,
        sizeof(ws_match_item_t)+vlen+1);
    res->result = result;
    res->next = NULL;
    if(!box->first) {
        box->first = res;
    } else {
        box->last->next = res;
    }
    box->last = res;
    char *d = res->item;
    for(const char *c = value; *c; ++c, ++d) {
        *d = tolower(*c);
    }
    *d = 0;
    return result;
}


size_t ws_match_hash(const char *s) {
    size_t res = 0;
    while (*s) {
	    res += (res<<1) + (res<<4) + (res<<7) + (res<<8) + (res<<24);
    	res ^= (size_t)*s++;
    }
    return res;
}

size_t ws_match_ihash(const char *s) {
    size_t res = 0;
    while (*s) {
	    res += (res<<1) + (res<<4) + (res<<7) + (res<<8) + (res<<24);
    	res ^= (size_t)(tolower(*s++));
    }
    return res;
}

size_t ws_match_rhash(const char *s) {
    size_t res = 0;
    const char *v = s + strlen(s) - 1;
    while(v >= s) {
	    res += (res<<1) + (res<<4) + (res<<7) + (res<<8) + (res<<24);
    	res ^= (size_t)*v--;
    }
    return res;
}

int ws_match_compile(void *rbox) {
    ws_match_box_t *box = (ws_match_box_t*)rbox;
    int i = 4;
    obstack_blank(&box->pieces,
        i*sizeof(ws_match_item_t*));
    while(TRUE) {
        ws_match_item_t **hashed = obstack_base(&box->pieces);
        bzero(hashed, sizeof(hashed[0])*i);
        ws_match_item_t *t = box->first;
        while(t) {
            size_t hashval = ws_match_hash(t->item) % i;
            if(!hashed[hashval]) {
                hashed[hashval] = t;
            } else {
                if(hashed[hashval] != t) {
                    break;
                }
            }
            t = t->next;
        }
        if(!t) {
            box->hash_size = i;
            break;
        }
        ++i;
        obstack_ptr_grow(&box->pieces, NULL);
    }
    box->hashed = obstack_finish(&box->pieces);
}

int ws_match(void *rbox, const char *value, size_t *result) {
    ws_match_box_t *box = (ws_match_box_t*)rbox;
    size_t hash = ws_match_hash(value);
    ws_match_item_t *item = box->hashed[hash % box->hash_size];
    if(!item || strcmp(value, item->item)) {
        return FALSE;
    }
    if(result) {
        *result = item->result;
    }
    return TRUE;
}

int ws_imatch(void *rbox, const char *value, size_t *result) {
    ws_match_box_t *box = (ws_match_box_t*)rbox;
    size_t hash = ws_match_ihash(value);
    ws_match_item_t *item = box->hashed[hash % box->hash_size];
    if(!item || strcasecmp(value, item->item)) {
        return FALSE;
    }
    if(result) {
        *result = item->result;
    }
    return TRUE;
}

void *ws_fuzzy_new() {
    ws_fuzzy_box_t *box = (ws_fuzzy_box_t*)malloc(sizeof(ws_fuzzy_box_t));
    if(!box) {
        return NULL;
    }
    obstack_init(&box->pieces);
    box->hash_size = 0;
    box->first = NULL;
    box->last = NULL;
    box->maxlen = 0;
    return box;
}
void ws_fuzzy_free(void *hint) {
    ws_fuzzy_box_t *box = hint;
    obstack_free(&box->pieces, NULL);
    free(box);
}

size_t ws_fuzzy_add(void *rbox, const char *value, int prefix, size_t result) {
    ws_fuzzy_box_t *box = (ws_fuzzy_box_t*)rbox;
    assert(!box->hash_size);
    ws_fuzzy_item_t *t = box->first;
    while(t) {
        if(!strcmp(value, t->item)) {
            if(prefix) {
                if(t->flags & WS_F_PREFIX) {
                    return t->prefix_result;
                } else {
                    t->flags |= WS_F_PREFIX;
                    t->prefix_result = result;
                    return result;
                }
            } else {
                if(t->flags & WS_F_EXACT) {
                    return t->exact_result;
                } else {
                    t->flags |= WS_F_EXACT;
                    t->exact_result = result;
                    return result;
                }
            }
        }
        t = t->next;
    }
    int len = strlen(value);
    ws_fuzzy_item_t *res = (ws_fuzzy_item_t*)obstack_alloc(&box->pieces,
        sizeof(ws_fuzzy_item_t)+len+1);
    res->len = len;
    if(len > box->maxlen) {
        box->maxlen = len;
    }
    if(prefix) {
        res->flags = WS_F_PREFIX;
        res->prefix_result = result;
    } else {
        res->flags = WS_F_EXACT;
        res->exact_result = result;
    }
    res->next = NULL;
    if(!box->first) {
        box->first = res;
    } else {
        box->last->next = res;
    }
    box->last = res;
    strcpy(res->item, value);
    return result;
}

int ws_rfuzzy_compile(void *rbox) {
    ws_fuzzy_box_t *box = rbox;
    char sizes[box->maxlen+1];
    bzero(sizes, box->maxlen+1);
    int size_cnt = 0;
    int i = 4;
    obstack_blank(&box->pieces, i*sizeof(ws_fuzzy_item_t*));
    while(TRUE) {
        ws_fuzzy_item_t **hashed = obstack_base(&box->pieces);
        bzero(hashed, sizeof(hashed[0])*i);
        ws_fuzzy_item_t *t = box->first;
        while(t) {
            size_t hashval = ws_match_rhash(t->item) % i;
            size_t len = strlen(t->item);
            if(!sizes[len]) {
                sizes[len] = 1;
                size_cnt += 1;
            }
            if(!hashed[hashval]) {
                hashed[hashval] = t;
            } else {
                if(hashed[hashval] != t) {
                    break;
                }
            }
            t = t->next;
        }
        if(!t) {
            break;
        }
        ++i;
        obstack_ptr_grow(&box->pieces, NULL);
    }
    box->hash_size = i;
    box->hashed = obstack_finish(&box->pieces);
    box->sizes = obstack_alloc(&box->pieces, sizeof(int)*size_cnt);
    int *tsizes = box->sizes;
    for(int i = 0; i <= box->maxlen; ++i) {
        if(sizes[i]) {
            *tsizes++ = i;
        }
    }
    box->nsizes = size_cnt;
}

int ws_fuzzy_compile(void *rbox) {
    ws_fuzzy_box_t *box = rbox;
    char sizes[box->maxlen+1];
    bzero(sizes, box->maxlen+1);
    int size_cnt = 0;
    int i = 4;
    obstack_blank(&box->pieces, i*sizeof(ws_fuzzy_item_t*));
    while(TRUE) {
        ws_fuzzy_item_t **hashed = obstack_base(&box->pieces);
        bzero(hashed, sizeof(hashed[0])*i);
        ws_fuzzy_item_t *t = box->first;
        while(t) {
            size_t hashval = ws_match_hash(t->item) % i;
            size_t len = strlen(t->item);
            if(!sizes[len]) {
                sizes[len] = 1;
                size_cnt += 1;
            }
            if(!hashed[hashval]) {
                hashed[hashval] = t;
            } else {
                if(hashed[hashval] != t) {
                    break;
                }
            }
            t = t->next;
        }
        if(!t) {
            break;
        }
        ++i;
        obstack_ptr_grow(&box->pieces, NULL);
    }
    box->hash_size = i;
    box->hashed = obstack_finish(&box->pieces);
    box->sizes = obstack_alloc(&box->pieces, sizeof(int)*size_cnt);
    int *tsizes = box->sizes;
    for(int i = 0; i <= box->maxlen; ++i) {
        if(sizes[i]) {
            *tsizes++ = i;
        }
    }
    box->nsizes = size_cnt;
}

int ws_fuzzy(void *rbox, const char *value, size_t *result) {
    ws_fuzzy_box_t *box = rbox;
    assert(box->nsizes);
    size_t hashes[box->nsizes];

    size_t res = 0;
    const char *s = value;
    int i = 0;
    size_t *ctarg = hashes;
    int sizei = 0;
    int csize = box->sizes[sizei];
    if(i == csize) { // if default match exists
        *ctarg++ = res;
        if(++sizei >= box->nsizes) {
            csize = -1;
        } else {
            csize = box->sizes[sizei];
        }
    }
    if(csize > 0) {
        while (*s) {
            res += (res<<1) + (res<<4) + (res<<7) + (res<<8) + (res<<24);
            res ^= (size_t)*s++;
            ++i;
            if(i == csize) {
                *ctarg++ = res;
                if(++sizei >= box->nsizes) {
                    csize = -1;
                    break;
                } else {
                    csize = box->sizes[sizei];
                }
            }
        }
    }

    size_t hash = res;
    ws_fuzzy_item_t *item = box->hashed[hash % box->hash_size];
    if(item && !strcmp(value, item->item)) {
        if(item->flags & WS_F_EXACT) {
            *result = item->exact_result;
            return TRUE;
        } else {
            *result = item->prefix_result;
            return TRUE;
        }
    }

    if(sizei >= box->nsizes) {
        sizei = box->nsizes-1;
    } else {
        --sizei;
    }
    while(sizei >= 0) {
        item = box->hashed[hashes[sizei] % box->hash_size];
        if(item && item->len == box->sizes[sizei]
            && !strncmp(value, item->item, item->len)) {
            if(item->flags & WS_F_PREFIX) {
                *result = item->prefix_result;
                return TRUE;
            }
        }
        --sizei;
    }
    return FALSE;
}

int ws_rfuzzy(void *rbox, const char *value, size_t *result) {
    ws_fuzzy_box_t *box = rbox;
    assert(box->nsizes);
    size_t hashes[box->nsizes];

    size_t res = 0;
    size_t valuelen = strlen(value);
    const char *p = value + valuelen - 1;
    int i = 0;
    size_t *ctarg = hashes;
    int sizei = 0;
    int csize = box->sizes[sizei];
    if(i == csize) { // if default match exists
        *ctarg++ = res;
        if(++sizei >= box->nsizes) {
            csize = -1;
        } else {
            csize = box->sizes[sizei];
        }
    }
    if(csize > 0) {
        while (p >= value) {
            res += (res<<1) + (res<<4) + (res<<7) + (res<<8) + (res<<24);
            res ^= (size_t)*p--;
            ++i;
            if(i == csize) {
                *ctarg++ = res;
                if(++sizei >= box->nsizes) {
                    csize = -1;
                    break;
                } else {
                    csize = box->sizes[sizei];
                }
            }
        }
    }

    size_t hash = res;
    ws_fuzzy_item_t *item = box->hashed[hash % box->hash_size];
    if(item && !strcmp(value, item->item)) {
        if(item->flags & WS_F_EXACT) {
            *result = item->exact_result;
            return TRUE;
        } else {
            *result = item->prefix_result;
            return TRUE;
        }
    }

    if(sizei >= box->nsizes) {
        sizei = box->nsizes-1;
    } else {
        --sizei;
    }
    while(sizei >= 0) {
        item = box->hashed[hashes[sizei] % box->hash_size];
        if(item && item->len == box->sizes[sizei]
            && !strcmp(value+valuelen-item->len, item->item)) {
            if(item->flags & WS_F_PREFIX) {
                *result = item->prefix_result;
                return TRUE;
            }
        }
        --sizei;
    }
    return FALSE;
}
