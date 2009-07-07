#include <stdlib.h>
#include <unistd.h>
#include <check.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "../src/lldpd.h"

struct hmsg *h = NULL;

void
setup()
{
	h = (struct hmsg *)calloc(1, MAX_HMSGSIZE);
	fail_unless(h != NULL);
}

void teardown()
{
	free(h); h = NULL;
}

START_TEST (test_pack_byte)
{
	/* Packing a single byte */
	char byte = 18;
	void *p;
	p = (char*)&h->data;
	if (ctl_msg_pack_structure("b", &byte, sizeof(char),
		h, &p) == -1) {
		fail("unable to pack");
		return;
	}
	mark_point();
	p = (char*)&h->data;
	if (ctl_msg_unpack_structure("b", &byte, sizeof(char),
		h, &p) == -1) {
		fail("unable to unpack");
		return;
	}
	ck_assert_int_eq(byte, 18);
}
END_TEST

START_TEST (test_pack_word)
{
	/* Packing a single word */
	u_int16_t word = 7874;
	void *p;
	p = (char*)&h->data;
	if (ctl_msg_pack_structure("w", &word, sizeof(u_int16_t),
		h, &p) == -1) {
		fail("unable to pack");
		return;
	}
	mark_point();
	p = (char*)&h->data;
	if (ctl_msg_unpack_structure("w", &word, sizeof(u_int16_t),
		h, &p) == -1) {
		fail("unable to unpack");
		return;
	}
	ck_assert_int_eq(word, 7874);
}
END_TEST

START_TEST (test_pack_long)
{
	/* Packing a single long */
	u_int32_t l = 14523657;
	void *p;
	p = (char*)&h->data;
	if (ctl_msg_pack_structure("l", &l, sizeof(u_int32_t),
		h, &p) == -1) {
		fail("unable to pack");
		return;
	}
	mark_point();
	p = (char*)&h->data;
	if (ctl_msg_unpack_structure("l", &l, sizeof(u_int32_t),
		h, &p) == -1) {
		fail("unable to unpack");
		return;
	}
	ck_assert_int_eq(l, 14523657);
}
END_TEST

START_TEST (test_pack_time)
{
	/* Packing a single time_t */
	time_t t = time(NULL);
	time_t t2;
	void *p;
	t2 = t;
	p = (char*)&h->data;
	if (ctl_msg_pack_structure("t", &t, sizeof(time_t),
		h, &p) == -1) {
		fail("unable to pack");
		return;
	}
	mark_point();
	p = (char*)&h->data;
	if (ctl_msg_unpack_structure("t", &t, sizeof(time_t),
		h, &p) == -1) {
		fail("unable to unpack");
		return;
	}
	ck_assert_int_eq(t, t2);
}
END_TEST

START_TEST (test_pack_string)
{
	/* Packing a single string */
	char *s = "My simple string";
	char *rs;
	void *p;
	p = (char*)&h->data;
	if (ctl_msg_pack_structure("s", &s, sizeof(char *),
		h, &p) == -1) {
		fail("unable to pack");
		return;
	}
	mark_point();
	p = (char*)&h->data;
	if (ctl_msg_unpack_structure("s", &rs, sizeof(char *),
		h, &p) == -1) {
		fail("unable to unpack");
		return;
	}
	ck_assert_str_eq(s, rs);
	ck_assert_str_eq(rs, "My simple string");
	free(rs);
}
END_TEST

START_TEST (test_pack_null_string)
{
	/* Packing a single empty string */
	char *s = "";
	char *rs;
	void *p;
	p = (char*)&h->data;
	if (ctl_msg_pack_structure("s", &s, sizeof(char *),
		h, &p) == -1) {
		fail("unable to pack");
		return;
	}
	mark_point();
	p = (char*)&h->data;
	if (ctl_msg_unpack_structure("s", &rs, sizeof(char *),
		h, &p) == -1) {
		fail("unable to unpack");
		return;
	}
	ck_assert_str_eq(s, rs);
	ck_assert_int_eq(strlen(rs), 0);
	free(rs);
}
END_TEST

struct tpls {
	char *s;
	int l;
};

START_TEST (test_pack_len_string)
{
	/* Packing a single string with its length */
	struct tpls t;
	void *p;

	t.s = "My string";
	t.l = strlen(t.s);

	p = (char*)&h->data;
	if (ctl_msg_pack_structure("C", &t, sizeof(struct tpls),
		h, &p) == -1) {
		fail("unable to pack");
		return;
	}
	mark_point();
	p = (char*)&h->data;
	if (ctl_msg_unpack_structure("C", &t, sizeof(struct tpls),
		h, &p) == -1) {
		fail("unable to unpack");
		return;
	}
	ck_assert_int_eq(t.l, strlen("My string"));
	fail_unless(memcmp(t.s, "My string", t.l) == 0);
	free(t.s);
}
END_TEST

struct tps1 {
	u_int8_t a;
	u_int16_t b;
	u_int32_t c;
	u_int8_t d;
	void *e;
	u_int8_t f;
	time_t g;
};

START_TEST (test_pack_structures1)
{
	/* Test padding */
	struct tps1 t;
	void *p;
	t.a = 129;
	t.b = 37814;
	t.c = 3456781258;
	t.d = 14;
	t.e = &t;
	t.f = 47;
	t.g = 1246799447;

	p = (char*)&h->data;
	if (ctl_msg_pack_structure("bwlbPbt", &t, sizeof(struct tps1),
		h, &p) == -1) {
		fail("unable to pack");
		return;
	}
	mark_point();
	p = (char*)&h->data;
	if (ctl_msg_unpack_structure("bwlbPbt", &t, sizeof(struct tps1),
		h, &p) == -1) {
		fail("unable to unpack");
		return;
	}
	ck_assert_int_eq(t.a, 129);
	ck_assert_int_eq(t.b, 37814);
	ck_assert_int_eq(t.c, 3456781258);
	ck_assert_int_eq(t.d, 14);
	ck_assert_int_eq(t.f, 47);
	ck_assert_int_eq(t.g, 1246799447);
}
END_TEST

struct tps2 {
	u_int8_t a;
	void *b;
	u_int16_t c;
	void *d;
	u_int32_t e;
	void *f;
	time_t g;
	void *h;
	u_int8_t i;
};

START_TEST (test_pack_structures2)
{
	/* More padding */
	struct tps2 t;
	void *p;
	t.a = 129;
	t.c = 37814;
	t.e = 3456781258;
	t.g = 1246799447;
	t.i = 12;

	p = (char*)&h->data;
	if (ctl_msg_pack_structure("bPwPlPtPb", &t, sizeof(struct tps2),
		h, &p) == -1) {
		fail("unable to pack");
		return;
	}
	mark_point();
	p = (char*)&h->data;
	if (ctl_msg_unpack_structure("bPwPlPtPb", &t, sizeof(struct tps2),
		h, &p) == -1) {
		fail("unable to unpack");
		return;
	}
	ck_assert_int_eq(t.a, 129);
	ck_assert_int_eq(t.c, 37814);
	ck_assert_int_eq(t.e, 3456781258);
	ck_assert_int_eq(t.g, 1246799447);
	ck_assert_int_eq(t.i, 12);
}
END_TEST

struct tps3 {
	u_int8_t a;
	char *b;
	u_int16_t c;
	char *d;
	u_int32_t e;
	char *f;
	time_t g;
	char *h;
	u_int8_t i;
	char *j;
	int l;
	u_int8_t k;
	char *m;
};

START_TEST (test_pack_structures3)
{
	/* More padding, with strings */
	struct tps3 t;
	void *p;
	t.a = 129;
	t.b = "First string";
	t.c = 37814;
	t.d = "Second string";
	t.e = 3456781258;
	t.f = "Third string";
	t.g = 1246799447;
	t.h = "Fourth string";
	t.i = 12;
	t.j = "Fifth string";
	t.l = strlen(t.j);
	t.k = 89;
	t.m = "Last string";

	p = (char*)&h->data;
	if (ctl_msg_pack_structure("bswslstsbCbs", &t, sizeof(struct tps3),
		h, &p) == -1) {
		fail("unable to pack");
		return;
	}
	mark_point();
	p = (char*)&h->data;
	if (ctl_msg_unpack_structure("bswslstsbCbs", &t, sizeof(struct tps3),
		h, &p) == -1) {
		fail("unable to unpack");
		return;
	}
	ck_assert_int_eq(t.a, 129);
	ck_assert_str_eq(t.b, "First string");
	ck_assert_int_eq(t.c, 37814);
	ck_assert_str_eq(t.d, "Second string");
	ck_assert_int_eq(t.e, 3456781258);
	ck_assert_str_eq(t.f, "Third string");
	ck_assert_int_eq(t.g, 1246799447);
	ck_assert_str_eq(t.h, "Fourth string");
	ck_assert_int_eq(t.i, 12);
	ck_assert_int_eq(t.l, strlen("Fifth string"));
	fail_unless(memcmp(t.j, "Fifth string", t.l) == 0);
	ck_assert_int_eq(t.k, 89);
	ck_assert_str_eq(t.m, "Last string");
	free(t.b); free(t.d); free(t.f); free(t.h); free(t.j); free(t.m);
}
END_TEST

struct tps4_1 {
	u_int8_t a;
	u_int16_t b;
	u_int32_t c;
	time_t d;
	u_int8_t e;
	void *f;
	u_int8_t g;
	char *h;
	u_int8_t i;
};
#define TPS41 "(bwltbPbsb)"

struct tps4 {
	u_int8_t a;
	struct tps4_1 b;
	u_int16_t c;
	struct tps4_1 d;
	u_int32_t e;
	struct tps4_1 f;
	void *g;
	struct tps4_1 h;
	struct tps4_1 i;
	u_int8_t j;
};
#define TPS4 "b" TPS41 "w" TPS41 "l" TPS41 "P" TPS41 TPS41 "b"

START_TEST (test_pack_structures4)
{
	/* More padding, with substructures */
	struct tps4 t;
	void *p;
	t.a = 129;
	t.b.a = 178;
	t.b.b = 37894;
	t.b.c = 345678914;
	t.b.d = 345781741;
	t.b.e = 74;
	t.b.g = 78;
	t.b.h = "First string";
	t.b.i = 230;
	t.c = 37814;
	t.d.a = t.b.a + 1;
	t.d.b = t.b.b + 1;
	t.d.c = t.b.c + 1;
	t.d.d = t.b.d + 1;
	t.d.e = t.b.e + 1;
	t.d.g = t.b.g + 1;
	t.d.h = "Second string";
	t.d.i = t.b.i + 1;
	t.e = 3456781258;
	t.f.a = t.b.a + 2;
	t.f.b = t.b.b + 2;
	t.f.c = t.b.c + 2;
	t.f.d = t.b.d + 2;
	t.f.e = t.b.e + 2;
	t.f.g = t.b.g + 2;
	t.f.h = "Third string";
	t.f.i = t.b.i + 2;
	t.h.a = t.b.a + 3;
	t.h.b = t.b.b + 3;
	t.h.c = t.b.c + 3;
	t.h.d = t.b.d + 3;
	t.h.e = t.b.e + 3;
	t.h.g = t.b.g + 3;
	t.h.h = "Fourth string";
	t.h.i = t.b.i + 3;
	t.i.a = t.b.a + 4;
	t.i.b = t.b.b + 4;
	t.i.c = t.b.c + 4;
	t.i.d = t.b.d + 4;
	t.i.e = t.b.e + 4;
	t.i.g = t.b.g + 4;
	t.i.h = "Fifth string";
	t.i.i = t.b.i + 4;
	t.j = 12;

	p = (char*)&h->data;
	if (ctl_msg_pack_structure(TPS4, &t, sizeof(struct tps4),
		h, &p) == -1) {
		fail("unable to pack");
		return;
	}
	mark_point();
	p = (char*)&h->data;
	if (ctl_msg_unpack_structure(TPS4, &t, sizeof(struct tps4),
		h, &p) == -1) {
		fail("unable to unpack");
		return;
	}

	ck_assert_int_eq(t.a, 129);
	ck_assert_int_eq(t.b.a, 178);
	ck_assert_int_eq(t.b.b, 37894);
	ck_assert_int_eq(t.b.c, 345678914);
	ck_assert_int_eq(t.b.d, 345781741);
	ck_assert_int_eq(t.b.e, 74);
	ck_assert_int_eq(t.b.g, 78);
	ck_assert_str_eq(t.b.h, "First string");
	ck_assert_int_eq(t.b.i, 230);
	ck_assert_int_eq(t.c, 37814);
	ck_assert_int_eq(t.d.a, t.b.a + 1);
	ck_assert_int_eq(t.d.b, t.b.b + 1);
	ck_assert_int_eq(t.d.c, t.b.c + 1);
	ck_assert_int_eq(t.d.d, t.b.d + 1);
	ck_assert_int_eq(t.d.e, t.b.e + 1);
	ck_assert_int_eq(t.d.g, t.b.g + 1);
	ck_assert_str_eq(t.d.h, "Second string");
	ck_assert_int_eq(t.d.i, t.b.i + 1);
	ck_assert_int_eq(t.e, 3456781258);
	ck_assert_int_eq(t.f.a, t.b.a + 2);
	ck_assert_int_eq(t.f.b, t.b.b + 2);
	ck_assert_int_eq(t.f.c, t.b.c + 2);
	ck_assert_int_eq(t.f.d, t.b.d + 2);
	ck_assert_int_eq(t.f.e, t.b.e + 2);
	ck_assert_int_eq(t.f.g, t.b.g + 2);
	ck_assert_str_eq(t.f.h, "Third string");
	ck_assert_int_eq(t.f.i, t.b.i + 2);
	ck_assert_int_eq(t.h.a, t.b.a + 3);
	ck_assert_int_eq(t.h.b, t.b.b + 3);
	ck_assert_int_eq(t.h.c, t.b.c + 3);
	ck_assert_int_eq(t.h.d, t.b.d + 3);
	ck_assert_int_eq(t.h.e, t.b.e + 3);
	ck_assert_int_eq(t.h.g, t.b.g + 3);
	fail_unless(strcmp(t.h.h, "Fourth string") == 0);
	ck_assert_int_eq(t.h.i, t.b.i + 3);
	ck_assert_int_eq(t.i.a, t.b.a + 4);
	ck_assert_int_eq(t.i.b, t.b.b + 4);
	ck_assert_int_eq(t.i.c, t.b.c + 4);
	ck_assert_int_eq(t.i.d, t.b.d + 4);
	ck_assert_int_eq(t.i.e, t.b.e + 4);
	ck_assert_int_eq(t.i.g, t.b.g + 4);
	ck_assert_str_eq(t.i.h, "Fifth string");
	ck_assert_int_eq(t.i.i, t.b.i + 4);
	ck_assert_int_eq(t.j, 12);
	free(t.i.h); free(t.h.h); free(t.f.h); free(t.d.h); free(t.b.h);
}
END_TEST

struct tps51 {
	u_int8_t a;
	u_int16_t b;
	u_int32_t c;
	u_int8_t e;
	time_t f;
	u_int16_t g;
	u_int8_t h;
	u_int32_t i;
	u_int16_t j;
};
#define TPS51 "(bwlbtwblw)"

struct tps52 {
	u_int8_t a;
	struct tps51 b;
	u_int16_t c;
	struct tps51 d;
	u_int32_t e;
	struct tps51 f;
	struct tps51 g;
	u_int8_t h;
};
#define TPS52 "(b" TPS51 "w" TPS51 "l" TPS51 TPS51 "b)"

struct tps53 {
	u_int8_t a;
	struct tps52 b;
	u_int16_t c;
	struct tps52 d;
	u_int32_t e;
	struct tps51 f;
	struct tps52 g;
	u_int8_t h;
};
#define TPS53 "(b" TPS52 "w" TPS52 "l" TPS51 TPS52 "b)"

struct tps5 {
	u_int8_t a;
	struct tps51 b;
	u_int16_t c;
	struct tps53 d;
	u_int32_t e;
	struct tps53 f;
	struct tps53 g;
	u_int8_t h;
};
#define TPS5 "(b" TPS51 "w" TPS53 "l" TPS53 TPS53 "b)"

START_TEST (test_pack_structures5)
{
	/* More padding, with recursive substructures */
	struct tps5 t;
	struct tps5 tc;
	int f, n;
	void *p;

	f = open("/dev/urandom", O_RDONLY);
	if (f == -1) {
		fail("unable to open /dev/urandom");
		return;
	}
	n = read(f, &t, sizeof(struct tps5));
	if (n != sizeof(struct tps5)) {
		fail("Should have read %d bytes from /dev/random but got %d",
		    sizeof(struct tps5), n);
		close(f);
		return;
	}
	memcpy(&tc, &t, sizeof(struct tps5));
	close(f);

	p = (char*)&h->data;
	if (ctl_msg_pack_structure(TPS5, &t, sizeof(struct tps5),
		h, &p) == -1) {
		fail("unable to pack");
		return;
	}
	mark_point();
	p = (char*)&h->data;
	if (ctl_msg_unpack_structure(TPS5, &t, sizeof(struct tps5),
		h, &p) == -1) {
		fail("unable to unpack");
		return;
	}

	fail_unless(memcmp(&t, &tc, sizeof(struct tps5)) == 0);
}
END_TEST

struct tpl {
	TAILQ_ENTRY(tpl) next;
	u_int16_t a;
	u_int8_t b;
	u_int32_t c;
	char *e;
	u_int8_t d;
};
#define TPL "(Lwblsb)"

START_TEST (test_pack_empty_list)
{
	TAILQ_HEAD(, tpl) l;
	void *p;

	TAILQ_INIT(&l);
	p = (char*)&h->data;
	if (ctl_msg_pack_list(TPL, &l, sizeof(struct tpl),
		h, &p) == -1) {
		fail("unable to pack");
		return;
	}
	mark_point();
	p = (char*)&h->data;
	if (ctl_msg_unpack_list(TPL, &l, sizeof(struct tpl),
		h, &p) == -1) {
		fail("unable to unpack");
		return;
	}

	fail_unless(TAILQ_EMPTY(&l));
}
END_TEST

START_TEST (test_pack_list)
{
	TAILQ_HEAD(, tpl) l;
	struct tpl tpl1, tpl2, tpl3;
	struct tpl *tpl4;
	void *p;
	int count;

	TAILQ_INIT(&l);
	tpl1.a = 47241;
	tpl1.b = 147;
	tpl1.c = 1474142364;
	tpl1.d = 198;
	tpl1.e = "First string";
	mark_point();
	TAILQ_INSERT_TAIL(&l, &tpl1, next);
	tpl2.a = tpl1.a+1;
	tpl2.b = tpl1.b+1;
	tpl2.c = tpl1.c+1;
	tpl2.d = tpl1.d+1;
	tpl2.e = "Second string";
	mark_point();
	TAILQ_INSERT_TAIL(&l, &tpl2, next);
	tpl3.a = tpl1.a+2;
	tpl3.b = tpl1.b+2;
	tpl3.c = tpl1.c+2;
	tpl3.d = tpl1.d+2;
	tpl3.e = "Last string";
	mark_point();
	TAILQ_INSERT_TAIL(&l, &tpl3, next);

	mark_point();
	p = (char*)&h->data;
	if (ctl_msg_pack_list(TPL, &l, sizeof(struct tpl),
		h, &p) == -1) {
		fail("unable to pack");
		return;
	}
	mark_point();
	p = (char*)&h->data;
	if (ctl_msg_unpack_list(TPL, &l, sizeof(struct tpl),
		h, &p) == -1) {
		fail("unable to unpack");
		return;
	}

	count = 0;
	TAILQ_FOREACH(tpl4, &l, next) {
		mark_point();
		ck_assert_int_eq(tpl4->a, tpl1.a+count);
		ck_assert_int_eq(tpl4->b, tpl1.b+count);
		ck_assert_int_eq(tpl4->c, tpl1.c+count);
		ck_assert_int_eq(tpl4->d, tpl1.d+count);
		switch (count) {
		case 0:
			ck_assert_str_eq(tpl4->e, "First string");
			break;
		case 1:
			ck_assert_str_eq(tpl4->e, "Second string");
			break;
		case 2:
			ck_assert_str_eq(tpl4->e, "Last string");
			break;
		default:
			fail("Should not be there... List too long.");
			break;
		}
		count++;
	}

	ck_assert_int_eq(count, 3);
}
END_TEST

Suite *
pack_suite(void)
{
	Suite *s = suite_create("Packing");

	/* Single objects packing/unpacking */
	TCase *tc_core = tcase_create("Single objects");
	tcase_add_checked_fixture(tc_core, setup, teardown);
	tcase_add_test(tc_core, test_pack_byte);
	tcase_add_test(tc_core, test_pack_word);
	tcase_add_test(tc_core, test_pack_long);
	tcase_add_test(tc_core, test_pack_time);
	tcase_add_test(tc_core, test_pack_string);
	tcase_add_test(tc_core, test_pack_null_string);
	tcase_add_test(tc_core, test_pack_len_string);
	suite_add_tcase(s, tc_core);

	/* Complex structure packing/unpacking */
	TCase *tc_structures = tcase_create("Structures");
	tcase_add_checked_fixture(tc_structures, setup, teardown);
	tcase_add_test(tc_structures, test_pack_structures1);
	tcase_add_test(tc_structures, test_pack_structures2);
	tcase_add_test(tc_structures, test_pack_structures3);
	tcase_add_test(tc_structures, test_pack_structures4);
	tcase_add_test(tc_structures, test_pack_structures5);
	suite_add_tcase(s, tc_structures);

	/* List packing/unpacking */
	TCase *tc_lists = tcase_create("Lists");
	tcase_add_checked_fixture(tc_lists, setup, teardown);
	tcase_add_test(tc_lists, test_pack_empty_list);
	tcase_add_test(tc_lists, test_pack_list);
	suite_add_tcase(s, tc_lists);

	return s;
}

int
main()
{
	int number_failed;
	Suite *s = pack_suite ();
	SRunner *sr = srunner_create (s);
	srunner_run_all (sr, CK_ENV);
	number_failed = srunner_ntests_failed (sr);
	srunner_free (sr);
	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
