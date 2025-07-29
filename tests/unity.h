#ifndef UNITY_H
#define UNITY_H
#include <assert.h>
#include <string.h>
#include <stdio.h>
#define UNITY_BEGIN() 0
#define UNITY_END() (printf("All tests passed\n"), 0)
#define TEST_ASSERT_EQUAL(exp, act) assert((exp) == (act))
#define TEST_ASSERT_EQUAL_STRING(exp, act) assert(strcmp((exp), (act)) == 0)
#endif
