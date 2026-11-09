/* -*- mode: c; c-file-style: "openbsd" -*- */
/*
 * Copyright (c) 2026 aravindor <aravindor@gmail.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <check.h>

#include "../src/daemon/lldpd.h"
#include "../src/daemon/frame.h"

static const u_int8_t data[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 };

/* Copy `size' bytes of `data' into a buffer of exactly this size, so that a
 * read past its end is caught when running with AddressSanitizer. */
static u_int8_t *
frame_new(size_t size)
{
	u_int8_t *frame = malloc(size);
	fail_unless(frame != NULL);
	memcpy(frame, data, size);
	return frame;
}

START_TEST(test_peek_in_bounds)
{
	u_int8_t *frame = frame_new(sizeof(data));
	u_int8_t *pos = frame, *saved;
	int length = sizeof(data);
	u_int8_t bytes[2];
	u_int32_t v;

	v = PEEK_UINT8;
	ck_assert_int_eq(v, 0x01);
	v = PEEK_UINT16;
	ck_assert_int_eq(v, 0x0203);
	v = PEEK_UINT32;
	ck_assert_int_eq(v, 0x04050607);
	(void)PEEK_SAVE(saved);
	PEEK_BYTES(bytes, sizeof(bytes));
	ck_assert_int_eq(bytes[0], 0x08);
	ck_assert_int_eq(bytes[1], 0x09);
	ck_assert_int_eq(length, 0);
	PEEK_RESTORE(saved);
	ck_assert_int_eq(length, 2);
	PEEK_DISCARD_UINT16;
	ck_assert_int_eq(length, 0);
	fail_unless(pos == frame + sizeof(data));
	free(frame);
}
END_TEST

START_TEST(test_peek_past_end)
{
	u_int8_t *frame = frame_new(3);
	u_int8_t *pos = frame;
	int length = 3;
	u_int32_t v;

	v = PEEK_UINT16;
	ck_assert_int_eq(v, 0x0102);
	/* Only one byte left */
	v = PEEK_UINT16;
	ck_assert_int_eq(v, 0);
	ck_assert_int_eq(length, -1);
	fail_unless(pos == frame + 2);
	/* Once truncated, nothing else can be read */
	v = PEEK_UINT8;
	ck_assert_int_eq(v, 0);
	ck_assert_int_eq(length, -1);
	fail_unless(pos == frame + 2);
	free(frame);
}
END_TEST

START_TEST(test_peek_uint32_past_end)
{
	u_int8_t *frame = frame_new(3);
	u_int8_t *pos = frame;
	int length = 3;
	u_int32_t v;

	v = PEEK_UINT32;
	ck_assert_int_eq(v, 0);
	ck_assert_int_eq(length, -1);
	fail_unless(pos == frame);
	free(frame);
}
END_TEST

START_TEST(test_peek_bytes_past_end)
{
	u_int8_t *frame = frame_new(4);
	u_int8_t *pos = frame;
	int length = 4;
	u_int8_t bytes[8];

	memset(bytes, 0xaa, sizeof(bytes));
	PEEK_BYTES(bytes, sizeof(bytes));
	ck_assert_int_eq(length, -1);
	fail_unless(pos == frame);
	ck_assert_int_eq(bytes[0], 0xaa);
	ck_assert_int_eq(bytes[7], 0xaa);
	free(frame);
}
END_TEST

START_TEST(test_peek_cmp_past_end)
{
	u_int8_t *frame = frame_new(4);
	u_int8_t *pos = frame;
	int length = 4;

	fail_unless(PEEK_CMP(data, 6) != 0);
	ck_assert_int_eq(length, -1);
	fail_unless(pos == frame);
	free(frame);
}
END_TEST

START_TEST(test_peek_discard_invalid)
{
	u_int8_t *frame = frame_new(4);
	u_int8_t *pos = frame;
	int length = 4;
	u_int32_t v;

	/* Skipping past the end */
	PEEK_DISCARD(5);
	ck_assert_int_eq(length, -1);
	fail_unless(pos == frame);

	/* Going backward */
	length = 4;
	PEEK_DISCARD_UINT16;
	PEEK_DISCARD(-2);
	ck_assert_int_eq(length, -1);
	fail_unless(pos == frame + 2);
	v = PEEK_UINT8;
	ck_assert_int_eq(v, 0);
	free(frame);
}
END_TEST

START_TEST(test_peek_restore_after_failure)
{
	u_int8_t *frame = frame_new(4);
	u_int8_t *pos = frame, *saved;
	int length = 4;
	u_int32_t v;

	(void)PEEK_SAVE(saved);
	PEEK_DISCARD_UINT16;
	v = PEEK_UINT32;
	ck_assert_int_eq(v, 0);
	ck_assert_int_eq(length, -1);
	/* Going back does not hide the error */
	PEEK_RESTORE(saved);
	ck_assert_int_eq(length, -1);
	v = PEEK_UINT8;
	ck_assert_int_eq(v, 0);
	free(frame);
}
END_TEST

static Suite *
frame_suite(void)
{
	Suite *s = suite_create("Frame parsing");

	TCase *tc_peek = tcase_create("PEEK macros");
	tcase_add_test(tc_peek, test_peek_in_bounds);
	tcase_add_test(tc_peek, test_peek_past_end);
	tcase_add_test(tc_peek, test_peek_uint32_past_end);
	tcase_add_test(tc_peek, test_peek_bytes_past_end);
	tcase_add_test(tc_peek, test_peek_cmp_past_end);
	tcase_add_test(tc_peek, test_peek_discard_invalid);
	tcase_add_test(tc_peek, test_peek_restore_after_failure);
	suite_add_tcase(s, tc_peek);

	return s;
}

int
main()
{
	int number_failed;
	Suite *s = frame_suite();
	SRunner *sr = srunner_create(s);
	srunner_run_all(sr, CK_ENV);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);
	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
