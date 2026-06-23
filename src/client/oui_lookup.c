/* -*- mode: c; c-file-style: "openbsd" -*- */
/*
 * Copyright (c) 2024
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

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <errno.h>

#include "../log.h"
#include "oui_lookup.h"

#ifdef OUI_DATABASE_PATH

/* Simple hash table for OUI lookup */
#define OUI_HASH_SIZE 4096

struct oui_entry {
	uint32_t oui_key;  /* 24-bit OUI as 32-bit key */
	char *vendor;
	struct oui_entry *next;
};

static struct oui_entry *oui_hash[OUI_HASH_SIZE] = { NULL };
static int oui_initialized = 0;

/* Hash function for OUI */
static uint32_t
oui_hash_key(const uint8_t *oui)
{
	return ((uint32_t)oui[0] << 16) | ((uint32_t)oui[1] << 8) | (uint32_t)oui[2];
}

/* Get hash bucket index */
static unsigned int
oui_hash_index(uint32_t key)
{
	return key % OUI_HASH_SIZE;
}

/* Parse hex string to bytes */
static int
parse_hex_oui(const char *hex_str, uint8_t *oui)
{
	unsigned int val;
	char *endptr;

	if (!hex_str || strlen(hex_str) != 6) return -1;

	val = strtoul(hex_str, &endptr, 16);
	if (*endptr != '\0' || val > 0xFFFFFF) return -1;

	oui[0] = (val >> 16) & 0xFF;
	oui[1] = (val >> 8) & 0xFF;
	oui[2] = val & 0xFF;

	return 0;
}

/* Parse CSV line and extract OUI and vendor name */
static int
parse_csv_line(char *line, uint8_t *oui, char **vendor)
{
	char *p, *end;
	char *fields[4] = { NULL, NULL, NULL, NULL };
	int field = 0;
	int in_quotes = 0;

	/* Skip empty lines and comments */
	if (!line || line[0] == '\0' || line[0] == '#') return -1;

	/* Parse CSV fields (handles quoted fields with commas) */
	p = line;
	fields[0] = p;  /* Registry */
	field = 1;

	while (*p && field < 4) {
		if (*p == '"') {
			in_quotes = !in_quotes;
			p++;
			continue;
		}
		if (!in_quotes && *p == ',') {
			*p = '\0';
			if (field < 4) {
				fields[field] = p + 1;
			}
			field++;
			p++;
			continue;
		}
		p++;
	}

	/* We need at least Registry, Assignment, and Organization Name */
	if (!fields[0] || !fields[1] || !fields[2]) return -1;

	/* Remove quotes from fields if present */
	for (field = 0; field < 3; field++) {
		if (fields[field] && fields[field][0] == '"') {
			fields[field]++;
			end = fields[field] + strlen(fields[field]) - 1;
			if (end >= fields[field] && *end == '"') {
				*end = '\0';
			}
		}
	}

	/* Parse OUI from Assignment field (second field) */
	if (parse_hex_oui(fields[1], oui) != 0) return -1;

	/* Extract vendor name (third field) */
	if (fields[2] && strlen(fields[2]) > 0) {
		/* Trim whitespace */
		while (isspace((unsigned char)*fields[2])) fields[2]++;
		end = fields[2] + strlen(fields[2]) - 1;
		while (end > fields[2] && isspace((unsigned char)*end)) {
			*end = '\0';
			end--;
		}
		if (strlen(fields[2]) > 0) {
			*vendor = fields[2];
			return 0;
		}
	}

	return -1;
}

/* Load OUI database from CSV file */
static int
oui_load_database(const char *path)
{
	FILE *fp;
	char *line = NULL;
	size_t len = 0;
	ssize_t read;
	uint8_t oui[3];
	char *vendor;
	uint32_t key;
	unsigned int idx;
	struct oui_entry *entry;
	int count = 0;
	int line_num = 0;

	fp = fopen(path, "r");
	if (!fp) {
		log_warn("oui_lookup", "cannot open OUI database: %s: %s",
		    path, strerror(errno));
		return -1;
	}

	/* Skip header line */
	if (getline(&line, &len, fp) == -1) {
		fclose(fp);
		free(line);
		return -1;
	}
	line_num++;

	while ((read = getline(&line, &len, fp)) != -1) {
		line_num++;
		if (read > 0 && line[read - 1] == '\n') {
			line[read - 1] = '\0';
		}

		vendor = NULL;
		if (parse_csv_line(line, oui, &vendor) == 0 && vendor) {
			key = oui_hash_key(oui);
			idx = oui_hash_index(key);

			/* Check if already exists */
			for (entry = oui_hash[idx]; entry; entry = entry->next) {
				if (entry->oui_key == key) {
					/* Update existing entry if vendor name is longer/more specific */
					if (strlen(vendor) > strlen(entry->vendor)) {
						free(entry->vendor);
						entry->vendor = strdup(vendor);
					}
					break;
				}
			}

			/* Add new entry */
			if (!entry) {
				entry = malloc(sizeof(struct oui_entry));
				if (!entry) {
					log_warn("oui_lookup", "out of memory");
					continue;
				}
				entry->oui_key = key;
				entry->vendor = strdup(vendor);
				if (!entry->vendor) {
					free(entry);
					log_warn("oui_lookup", "out of memory");
					continue;
				}
				entry->next = oui_hash[idx];
				oui_hash[idx] = entry;
				count++;
			}
		}
	}

	free(line);
	fclose(fp);

	log_debug("oui_lookup", "loaded %d OUI entries from %s", count, path);
	return 0;
}

void
oui_lookup_init(void)
{
	if (oui_initialized) return;

#ifdef OUI_DATABASE_PATH
	if (oui_load_database(OUI_DATABASE_PATH) == 0) {
		oui_initialized = 1;
	}
#endif
}

void
oui_lookup_cleanup(void)
{
	struct oui_entry *entry, *next;
	unsigned int i;

	if (!oui_initialized) return;

	for (i = 0; i < OUI_HASH_SIZE; i++) {
		entry = oui_hash[i];
		while (entry) {
			next = entry->next;
			free(entry->vendor);
			free(entry);
			entry = next;
		}
		oui_hash[i] = NULL;
	}

	oui_initialized = 0;
}

const char *
oui_lookup_vendor(const uint8_t *oui)
{
	uint32_t key;
	unsigned int idx;
	struct oui_entry *entry;

	if (!oui_initialized || !oui) return NULL;

	key = oui_hash_key(oui);
	idx = oui_hash_index(key);

	for (entry = oui_hash[idx]; entry; entry = entry->next) {
		if (entry->oui_key == key) {
			return entry->vendor;
		}
	}

	return NULL;
}

#else /* !OUI_DATABASE_PATH */

void
oui_lookup_init(void)
{
	/* No-op when OUI database is not available */
}

void
oui_lookup_cleanup(void)
{
	/* No-op when OUI database is not available */
}

const char *
oui_lookup_vendor(const uint8_t *oui)
{
	(void)oui;
	return NULL;
}

#endif /* OUI_DATABASE_PATH */
