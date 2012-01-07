#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include <website.h>

#define TRUE 1
#define FALSE 0

void testMatch() {
    void *m = ws_match_new();
    CU_ASSERT_EQUAL(ws_match_add(m, "One", 1), 1);
    CU_ASSERT_EQUAL(ws_match_add(m, "Two", 2), 2);
    CU_ASSERT_EQUAL(ws_match_add(m, "Three", 3), 3);
    ws_match_compile(m);
    size_t result;
    CU_ASSERT(ws_match(m, "One", &result));
    CU_ASSERT_EQUAL(result, 1);
    CU_ASSERT(ws_match(m, "Two", &result));
    CU_ASSERT_EQUAL(result, 2);
    CU_ASSERT(ws_match(m, "Three", &result));
    CU_ASSERT_EQUAL(result, 3);
    result = -1;
    CU_ASSERT_FALSE(ws_match(m, "three", &result));
    CU_ASSERT_EQUAL(result, -1);
    CU_ASSERT_FALSE(ws_match(m, "four", &result));
    CU_ASSERT_EQUAL(result, -1);
    CU_ASSERT_FALSE(ws_match(m, "another text", &result));
    CU_ASSERT_EQUAL(result, -1);
    ws_match_free(m);
}

void testMatchCompile() {
    void *m = ws_match_new();
    CU_ASSERT_EQUAL(ws_match_add(m, "One", 1), 1);
    CU_ASSERT_EQUAL(ws_match_add(m, "Two", 2), 2);
    CU_ASSERT_EQUAL(ws_match_add(m, "Three", 3), 3);
    CU_ASSERT_EQUAL(ws_match_add(m, "Three", 10), 3);
    ws_match_compile(m);
    size_t result;
    CU_ASSERT(ws_match(m, "One", &result));
    CU_ASSERT_EQUAL(result, 1);
    CU_ASSERT(ws_match(m, "Two", &result));
    CU_ASSERT_EQUAL(result, 2);
    CU_ASSERT(ws_match(m, "Three", &result));
    CU_ASSERT_EQUAL(result, 3);
    result = -1;
    CU_ASSERT_FALSE(ws_match(m, "three", &result));
    CU_ASSERT_EQUAL(result, -1);
    CU_ASSERT_FALSE(ws_match(m, "four", &result));
    CU_ASSERT_EQUAL(result, -1);
    CU_ASSERT_FALSE(ws_match(m, "another text", &result));
    CU_ASSERT_EQUAL(result, -1);
    ws_match_free(m);
}

void testIMatch() {
    void *m = ws_match_new();
    CU_ASSERT_EQUAL(ws_match_iadd(m, "One", 1), 1);
    CU_ASSERT_EQUAL(ws_match_iadd(m, "Two", 2), 2);
    CU_ASSERT_EQUAL(ws_match_iadd(m, "Three", 3), 3);
    ws_match_compile(m);
    size_t result;
    CU_ASSERT(ws_imatch(m, "One", &result));
    CU_ASSERT_EQUAL(result, 1);
    CU_ASSERT(ws_imatch(m, "Two", &result));
    CU_ASSERT_EQUAL(result, 2);
    CU_ASSERT(ws_imatch(m, "Three", &result));
    CU_ASSERT_EQUAL(result, 3);
    CU_ASSERT(ws_imatch(m, "tWo", &result));
    CU_ASSERT_EQUAL(result, 2);
    result = -1;
    CU_ASSERT_FALSE(ws_imatch(m, "four", &result));
    CU_ASSERT_EQUAL(result, -1);
    CU_ASSERT_FALSE(ws_imatch(m, "foUR", &result));
    CU_ASSERT_EQUAL(result, -1);
    CU_ASSERT_FALSE(ws_imatch(m, "another text", &result));
    CU_ASSERT_EQUAL(result, -1);
    ws_match_free(m);
}


void testIMatchCompile() {
    void *m = ws_match_new();
    CU_ASSERT_EQUAL(ws_match_iadd(m, "One", 1), 1);
    CU_ASSERT_EQUAL(ws_match_iadd(m, "Two", 2), 2);
    CU_ASSERT_EQUAL(ws_match_iadd(m, "Three", 3), 3);
    CU_ASSERT_EQUAL(ws_match_iadd(m, "three", 10), 3);
    CU_ASSERT_EQUAL(ws_match_iadd(m, "thREE", 15), 3);
    ws_match_compile(m);
    size_t result;
    CU_ASSERT(ws_imatch(m, "One", &result));
    CU_ASSERT_EQUAL(result, 1);
    CU_ASSERT(ws_imatch(m, "Two", &result));
    CU_ASSERT_EQUAL(result, 2);
    CU_ASSERT(ws_imatch(m, "Three", &result));
    CU_ASSERT_EQUAL(result, 3);
    CU_ASSERT(ws_imatch(m, "tWo", &result));
    CU_ASSERT_EQUAL(result, 2);
    CU_ASSERT(ws_imatch(m, "thREE", &result));
    CU_ASSERT_EQUAL(result, 3);
    result = -1;
    CU_ASSERT_FALSE(ws_imatch(m, "four", &result));
    CU_ASSERT_EQUAL(result, -1);
    CU_ASSERT_FALSE(ws_imatch(m, "foUR", &result));
    CU_ASSERT_EQUAL(result, -1);
    CU_ASSERT_FALSE(ws_imatch(m, "another text", &result));
    CU_ASSERT_EQUAL(result, -1);
    ws_match_free(m);
}

void testFuzzy() {
    void *m = ws_fuzzy_new();
    CU_ASSERT_EQUAL(ws_fuzzy_add(m, "/one", FALSE, 1), 1);
    CU_ASSERT_EQUAL(ws_fuzzy_add(m, "/two", TRUE, 2), 2);
    CU_ASSERT_EQUAL(ws_fuzzy_add(m, "/three", FALSE, 3), 3);
    CU_ASSERT_EQUAL(ws_fuzzy_add(m, "/three/", FALSE, 3), 3);
    CU_ASSERT_EQUAL(ws_fuzzy_add(m, "/three/", TRUE, 35), 35);
    CU_ASSERT_EQUAL(ws_fuzzy_add(m, "/three/seven", TRUE, 37), 37);
    ws_fuzzy_compile(m);
    size_t result;
    CU_ASSERT(ws_fuzzy(m, "/one", &result));
    CU_ASSERT_EQUAL(result, 1);
    result = -1;
    CU_ASSERT_FALSE(ws_fuzzy(m, "/one_and_half", &result));
    CU_ASSERT_EQUAL(result, -1);
    CU_ASSERT_FALSE(ws_fuzzy(m, "/one/and/half", &result));
    CU_ASSERT_EQUAL(result, -1);
    CU_ASSERT(ws_fuzzy(m, "/two", &result));
    CU_ASSERT_EQUAL(result, 2);
    CU_ASSERT(ws_fuzzy(m, "/two_and_half", &result));
    CU_ASSERT_EQUAL(result, 2);
    CU_ASSERT(ws_fuzzy(m, "/two/and/half", &result));
    CU_ASSERT_EQUAL(result, 2);
    CU_ASSERT(ws_fuzzy(m, "/three", &result));
    CU_ASSERT_EQUAL(result, 3);
    result = -1;
    CU_ASSERT_FALSE(ws_fuzzy(m, "/three_and_half", &result));
    CU_ASSERT_EQUAL(result, -1);
    CU_ASSERT(ws_fuzzy(m, "/three/and/half", &result));
    CU_ASSERT_EQUAL(result, 35);
    CU_ASSERT(ws_fuzzy(m, "/three/seven", &result));
    CU_ASSERT_EQUAL(result, 37);
    CU_ASSERT(ws_fuzzy(m, "/three/seventeen", &result));
    CU_ASSERT_EQUAL(result, 37);
    ws_fuzzy_free(m);
}

void testDefault() {
    size_t result;
    void *m;

    m = ws_fuzzy_new();
    CU_ASSERT_EQUAL(ws_fuzzy_add(m, "", TRUE, 1), 1);
    CU_ASSERT_EQUAL(ws_fuzzy_add(m, "/two", TRUE, 2), 2);
    ws_fuzzy_compile(m);
    CU_ASSERT(ws_fuzzy(m, "/one", &result));
    CU_ASSERT_EQUAL(result, 1);
    CU_ASSERT(ws_fuzzy(m, "/", &result));
    CU_ASSERT_EQUAL(result, 1);
    CU_ASSERT(ws_fuzzy(m, "", &result));
    CU_ASSERT_EQUAL(result, 1);
    CU_ASSERT(ws_fuzzy(m, "/two", &result));
    CU_ASSERT_EQUAL(result, 2);
    CU_ASSERT(ws_fuzzy(m, "/two2", &result));
    CU_ASSERT_EQUAL(result, 2);
    ws_fuzzy_free(m);

    m = ws_fuzzy_new();
    CU_ASSERT_EQUAL(ws_fuzzy_add(m, "", TRUE, 1), 1);
    CU_ASSERT_EQUAL(ws_fuzzy_add(m, "example.com", TRUE, 2), 2);
    ws_rfuzzy_compile(m);
    CU_ASSERT(ws_rfuzzy(m, ".com", &result));
    CU_ASSERT_EQUAL(result, 1);
    CU_ASSERT(ws_rfuzzy(m, ".net", &result));
    CU_ASSERT_EQUAL(result, 1);
    CU_ASSERT(ws_rfuzzy(m, ".", &result));
    CU_ASSERT_EQUAL(result, 1);
    CU_ASSERT(ws_rfuzzy(m, "", &result));
    CU_ASSERT_EQUAL(result, 1);
    CU_ASSERT(ws_rfuzzy(m, "example.com", &result));
    CU_ASSERT_EQUAL(result, 2);
    CU_ASSERT(ws_rfuzzy(m, "test.example.com", &result));
    CU_ASSERT_EQUAL(result, 2);
    ws_fuzzy_free(m);
}

void testRFuzzy() {
    void *m = ws_fuzzy_new();
    CU_ASSERT_EQUAL(ws_fuzzy_add(m, "example.org", FALSE, 1), 1);
    CU_ASSERT_EQUAL(ws_fuzzy_add(m, "example.com", TRUE, 2), 2);
    CU_ASSERT_EQUAL(ws_fuzzy_add(m, "example.net", FALSE, 3), 3);
    CU_ASSERT_EQUAL(ws_fuzzy_add(m, ".example.net", FALSE, 3), 3);
    CU_ASSERT_EQUAL(ws_fuzzy_add(m, "hello.example.net", TRUE, 35), 35);
    CU_ASSERT_EQUAL(ws_fuzzy_add(m, "world.example.net", TRUE, 37), 37);
    ws_rfuzzy_compile(m);
    size_t result;
    CU_ASSERT(ws_rfuzzy(m, "example.org", &result));
    CU_ASSERT_EQUAL(result, 1);
    result = -1;
    CU_ASSERT_FALSE(ws_rfuzzy(m, "hello.example.org", &result));
    CU_ASSERT_EQUAL(result, -1);
    CU_ASSERT_FALSE(ws_rfuzzy(m, "join.example.org", &result));
    CU_ASSERT_EQUAL(result, -1);
    CU_ASSERT(ws_rfuzzy(m, "example.com", &result));
    CU_ASSERT_EQUAL(result, 2);
    CU_ASSERT(ws_rfuzzy(m, "test.example.com", &result));
    CU_ASSERT_EQUAL(result, 2);
    CU_ASSERT(ws_rfuzzy(m, "testexample.com", &result));
    CU_ASSERT_EQUAL(result, 2);
    CU_ASSERT(ws_rfuzzy(m, "example.net", &result));
    CU_ASSERT_EQUAL(result, 3);
    result = -1;
    CU_ASSERT_FALSE(ws_rfuzzy(m, "testexample.net", &result));
    CU_ASSERT_EQUAL(result, -1);
    CU_ASSERT(ws_rfuzzy(m, "hello.example.net", &result));
    CU_ASSERT_EQUAL(result, 35);
    CU_ASSERT(ws_rfuzzy(m, "world.example.net", &result));
    CU_ASSERT_EQUAL(result, 37);
    CU_ASSERT(ws_rfuzzy(m, "testworld.example.net", &result));
    CU_ASSERT_EQUAL(result, 37);
    ws_fuzzy_free(m);
}

int main(int argc, char **argv) {
   CU_pSuite pSuite = NULL;

   /* initialize the CUnit test registry */
   if (CUE_SUCCESS != CU_initialize_registry())
      return CU_get_error();

   /* add a suite to the registry */
   pSuite = CU_add_suite("Test", NULL, NULL);
   if (NULL == pSuite) {
      CU_cleanup_registry();
      return CU_get_error();
   }

   /* add the tests to the suite */
   if ((NULL == CU_add_test(pSuite, "Exact match", testMatch))
       || (NULL == CU_add_test(pSuite, "Exact compilation", testMatchCompile))
       || (NULL == CU_add_test(pSuite, "Case-insensitive match", testIMatch))
       || (NULL == CU_add_test(pSuite, "Case-insensitive compilation", testIMatchCompile))
       || (NULL == CU_add_test(pSuite, "Fuzzy match", testFuzzy))
       || (NULL == CU_add_test(pSuite, "Fuzzy reverse match", testRFuzzy))
       || (NULL == CU_add_test(pSuite, "Default fallback", testDefault))
       || 0) {
      CU_cleanup_registry();
      return CU_get_error();
   }

   /* Run all tests using the CUnit Basic interface */
   CU_basic_set_mode(CU_BRM_VERBOSE);
   CU_basic_run_tests();
   CU_cleanup_registry();
   return CU_get_error();
}
