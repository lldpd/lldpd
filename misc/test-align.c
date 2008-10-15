/* gcc -c test-align.c -S -o test-align.s */

#include <sys/types.h>

struct test1 {
  char a;
  char b;
} ;

struct test2 {
  char a;
  u_int16_t b;
} ;

struct test3 {
  char a;
  u_int32_t b;
} ;

struct test4 {
  char a;
  u_int64_t b;
} ;

struct test5 {
  char a;
  void *b;
} ;

struct test6 {
  char a;
  u_int16_t b;
  char c;
  char d;
  char e;
  char f;
  char g;
} ;


struct test1 test_1 = { 10, 20};
struct test2 test_2 = { 10, 20};
struct test3 test_3 = { 10, 20};
struct test4 test_4 = { 10, 20};
struct test5 test_5 = { 10, (void*)&test_4};
struct test6 test_6 = { 10, 15, 20, 30, 40, 50, 60};

int word_align = sizeof(struct test2) - sizeof(u_int16_t);
int long_align = sizeof(struct test3) - sizeof(u_int32_t);
int long_long_align = sizeof(struct test4) - sizeof(u_int64_t);
int pointer_align = sizeof(struct test5) - sizeof(void*);

int size = sizeof(struct test6);

