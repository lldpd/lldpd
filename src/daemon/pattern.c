/* -*- mode: c; c-file-style: "openbsd" -*- */
/*
 * Copyright (c) 2008 Vincent Bernat <bernat@luffy.cx>
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

#include "lldpd.h"

#include <string.h>
#include <fnmatch.h>

/**
 * Match a list of patterns.
 *
 * @param string   String to match against the list of patterns
 * @param patterns List of comma separated patterns. A pattern may
 *                 begin by `!` to negate it. In this case, it is
 *                 denied. A pattern may begin with `!!`. In this
 *                 case, it is allowed back. Each pattern will then be
 *                 matched against `fnmatch()` function.
 * @param found    Value to return if the pattern isn't found. Should be either
 *                 PATTERN_MATCH_DENIED or PATTERN_MACTH_DENIED.
 *
 * If a pattern is found matching and denied at the same time, it
 * will be denied. If it is both allowed and denied, it
 * will be allowed.
 *
 * @return PATTERN_MATCH_DENIED if the string matches a denied pattern which is not
 *         allowed or if the pattern wasn't found and `found` was set to
 *         PATTERN_MATCH_DENIED. Otherwise, return PATTERN_MATCH_ALLOWED unless the
 *         interface match is exact, in this case return PATTERN_MATCH_ALLOWED_EXACT.
 */
enum pattern_match_result
pattern_match(char *string, char *patterns, int found)
{
	char *pattern;
	int denied = 0;
	found = found ? PATTERN_MATCH_ALLOWED : PATTERN_MATCH_DENIED;

	if ((patterns = strdup(patterns)) == NULL) {
		log_warnx("interfaces", "unable to allocate memory");
		return PATTERN_MATCH_DENIED;
	}

	for (pattern = strtok(patterns, ","); pattern != NULL;
	     pattern = strtok(NULL, ",")) {
		if ((pattern[0] == '!') && (pattern[1] == '!') &&
		    (fnmatch(pattern + 2, string, 0) == 0)) {
			/* Allowed. No need to search further. */
			found = (strcmp(pattern + 2, string)) ?
			    PATTERN_MATCH_ALLOWED :
			    PATTERN_MATCH_ALLOWED_EXACT;
			break;
		}
		if ((pattern[0] == '!') && (fnmatch(pattern + 1, string, 0) == 0)) {
			denied = 1;
			found = PATTERN_MATCH_DENIED;
		} else if (!denied && fnmatch(pattern, string, 0) == 0) {
			if (!strcmp(pattern, string)) {
				found = PATTERN_MATCH_ALLOWED_EXACT;
			} else if (found < 2) {
				found = PATTERN_MATCH_ALLOWED;
			}
		}
	}

	free(patterns);
	return found;
}
