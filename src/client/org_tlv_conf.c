/* -*- mode: c; c-file-style: "openbsd" -*- */
/*
 * Copyright (c) 2026 Ciro Iriarte <ciro.iriarte+software@gmail.com>
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>

#include "../log.h"
#include "org_tlv_conf.h"

static struct org_tlv_def *def_list = NULL;
static struct org_tlv_vendor *vendor_list = NULL;

struct org_tlv_def *
org_tlv_conf_find(const uint8_t *oui, uint8_t subtype)
{
	struct org_tlv_def *d;
	for (d = def_list; d; d = d->next) {
		if (memcmp(d->oui, oui, 3) == 0 && d->subtype == subtype)
			return d;
	}
	return NULL;
}

struct org_tlv_vendor *
org_tlv_vendor_find(const uint8_t *oui)
{
	struct org_tlv_vendor *v;
	for (v = vendor_list; v; v = v->next) {
		if (memcmp(v->oui, oui, 3) == 0) return v;
	}
	return NULL;
}

static char *
strip(char *s)
{
	while (*s && isspace((unsigned char)*s))
		s++;
	char *end = s + strlen(s) - 1;
	while (end > s && isspace((unsigned char)*end))
		*end-- = '\0';
	return s;
}

/* Parse a field type string into enum */
static int
parse_field_type(const char *s, enum org_tlv_field_type *type)
{
	if (strcmp(s, "uint8") == 0) {
		*type = ORG_TLV_UINT8;
	} else if (strcmp(s, "uint16") == 0) {
		*type = ORG_TLV_UINT16;
	} else if (strcmp(s, "uint32") == 0) {
		*type = ORG_TLV_UINT32;
	} else if (strcmp(s, "string") == 0) {
		*type = ORG_TLV_STRING;
	} else if (strcmp(s, "ipv4") == 0) {
		*type = ORG_TLV_IPV4;
	} else if (strcmp(s, "mac") == 0) {
		*type = ORG_TLV_MAC;
	} else if (strcmp(s, "hex") == 0) {
		*type = ORG_TLV_HEX;
	} else {
		return -1;
	}
	return 0;
}

/* Parse "fields" value: e.g. "uint8:status, uint32:port_id" or just "string" */
static struct org_tlv_field *
parse_fields(const char *value)
{
	struct org_tlv_field *head = NULL, *tail = NULL;
	char *copy = strdup(value);
	if (!copy) return NULL;

	char *saveptr = NULL;
	char *token = strtok_r(copy, ",", &saveptr);
	while (token) {
		char *s = strip(token);
		if (*s == '\0') {
			token = strtok_r(NULL, ",", &saveptr);
			continue;
		}

		struct org_tlv_field *f = calloc(1, sizeof(*f));
		if (!f) break;

		/* Check for type:name format */
		char *colon = strchr(s, ':');
		if (colon) {
			*colon = '\0';
			char *type_str = strip(s);
			char *name_str = strip(colon + 1);
			if (parse_field_type(type_str, &f->type) < 0) {
				log_warnx("lldpctl",
				    "org-tlv config: unknown field type '%s'",
				    type_str);
				free(f);
				token = strtok_r(NULL, ",", &saveptr);
				continue;
			}
			f->name = strdup(name_str);
		} else {
			if (parse_field_type(s, &f->type) < 0) {
				log_warnx("lldpctl",
				    "org-tlv config: unknown field type '%s'", s);
				free(f);
				token = strtok_r(NULL, ",", &saveptr);
				continue;
			}
			f->name = NULL;
		}

		if (tail) {
			tail->next = f;
		} else {
			head = f;
		}
		tail = f;

		token = strtok_r(NULL, ",", &saveptr);
	}
	free(copy);
	return head;
}

/* Parse section header: "AA:BB:CC" (vendor) or "AA:BB:CC:subtype" (TLV def) */
static int
parse_section(const char *section, uint8_t *oui, int *subtype)
{
	unsigned int a, b, c, s;
	int n = sscanf(section, "%x:%x:%x:%u", &a, &b, &c, &s);
	if (n < 3) return -1;
	if (a > 255 || b > 255 || c > 255) return -1;
	oui[0] = (uint8_t)a;
	oui[1] = (uint8_t)b;
	oui[2] = (uint8_t)c;
	if (n == 4) {
		if (s > 255) return -1;
		*subtype = (int)s;
	} else {
		*subtype = -1; /* vendor-only section */
	}
	return 0;
}

static void
org_tlv_conf_load_file(const char *path)
{
	FILE *fp = fopen(path, "r");
	if (!fp) {
		log_warnx("lldpctl", "org-tlv config: cannot open %s", path);
		return;
	}

	log_debug("lldpctl", "org-tlv config: loading %s", path);

	char line[1024];
	uint8_t cur_oui[3] = { 0 };
	int cur_subtype = -1;
	int have_section = 0;

	/* Temporary storage for current section's key-value pairs */
	char *cur_name = NULL;
	char *cur_vendor = NULL;
	char *cur_fields = NULL;

	while (fgets(line, sizeof(line), fp)) {
		char *s = strip(line);
		if (*s == '\0' || *s == '#' || *s == ';') continue;

		/* Section header */
		if (*s == '[') {
			/* Save previous section first */
			if (have_section) {
				if (cur_subtype < 0 && cur_vendor) {
					/* Vendor definition */
					if (!org_tlv_vendor_find(cur_oui)) {
						struct org_tlv_vendor *v =
						    calloc(1, sizeof(*v));
						if (v) {
							memcpy(v->oui, cur_oui,
							    3);
							v->vendor_name =
							    cur_vendor;
							cur_vendor = NULL;
							v->next = vendor_list;
							vendor_list = v;
						}
					}
				} else if (cur_subtype >= 0 && cur_name) {
					/* TLV definition */
					struct org_tlv_def *d =
					    calloc(1, sizeof(*d));
					if (d) {
						memcpy(d->oui, cur_oui, 3);
						d->subtype =
						    (uint8_t)cur_subtype;
						d->name = cur_name;
						cur_name = NULL;
						d->fields = cur_fields ?
						    parse_fields(cur_fields) :
						    NULL;
						d->next = def_list;
						def_list = d;
					}
				}
			}
			free(cur_name);
			free(cur_vendor);
			free(cur_fields);
			cur_name = NULL;
			cur_vendor = NULL;
			cur_fields = NULL;

			char *end = strchr(s, ']');
			if (!end) {
				log_warnx("lldpctl",
				    "org-tlv config: malformed section in %s",
				    path);
				have_section = 0;
				continue;
			}
			*end = '\0';
			if (parse_section(s + 1, cur_oui, &cur_subtype) < 0) {
				log_warnx("lldpctl",
				    "org-tlv config: invalid section '%s' in %s",
				    s + 1, path);
				have_section = 0;
				continue;
			}
			have_section = 1;
			continue;
		}

		if (!have_section) continue;

		/* Key = value */
		char *eq = strchr(s, '=');
		if (!eq) continue;
		*eq = '\0';
		char *key = strip(s);
		char *val = strip(eq + 1);

		if (strcmp(key, "vendor") == 0) {
			free(cur_vendor);
			cur_vendor = strdup(val);
		} else if (strcmp(key, "name") == 0) {
			free(cur_name);
			cur_name = strdup(val);
		} else if (strcmp(key, "fields") == 0) {
			free(cur_fields);
			cur_fields = strdup(val);
		}
	}

	/* Save last section */
	if (have_section) {
		if (cur_subtype < 0 && cur_vendor) {
			if (!org_tlv_vendor_find(cur_oui)) {
				struct org_tlv_vendor *v = calloc(1, sizeof(*v));
				if (v) {
					memcpy(v->oui, cur_oui, 3);
					v->vendor_name = cur_vendor;
					cur_vendor = NULL;
					v->next = vendor_list;
					vendor_list = v;
				}
			}
		} else if (cur_subtype >= 0 && cur_name) {
			struct org_tlv_def *d = calloc(1, sizeof(*d));
			if (d) {
				memcpy(d->oui, cur_oui, 3);
				d->subtype = (uint8_t)cur_subtype;
				d->name = cur_name;
				cur_name = NULL;
				d->fields = cur_fields ? parse_fields(cur_fields) :
							 NULL;
				d->next = def_list;
				def_list = d;
			}
		}
	}
	free(cur_name);
	free(cur_vendor);
	free(cur_fields);
	fclose(fp);
}

static int
conf_filter(const struct dirent *dir)
{
	size_t len = strlen(dir->d_name);
	if (len < 5) return 0;
	if (strcmp(dir->d_name + len - 5, ".conf")) return 0;
	return 1;
}

void
org_tlv_conf_load(const char *dir)
{
	struct stat statbuf;
	if (stat(dir, &statbuf) == -1 || !S_ISDIR(statbuf.st_mode)) {
		log_debug("lldpctl", "org-tlv config: directory %s not found", dir);
		return;
	}

	struct dirent **namelist = NULL;
	int n = scandir(dir, &namelist, conf_filter, alphasort);
	if (n < 0) {
		log_debug("lldpctl",
		    "org-tlv config: unable to read directory %s", dir);
		return;
	}
	for (int i = 0; i < n; i++) {
		char *fullname;
		if (asprintf(&fullname, "%s/%s", dir, namelist[i]->d_name) != -1) {
			org_tlv_conf_load_file(fullname);
			free(fullname);
		}
		free(namelist[i]);
	}
	free(namelist);
}

void
display_org_tlv_from_def(struct writer *w, struct org_tlv_def *def,
    const uint8_t *data, int datalen)
{
	int pos = 0;

	/* If there's only one field with no name, use simple tag_datatag */
	if (def->fields && !def->fields->next && !def->fields->name) {
		struct org_tlv_field *f = def->fields;
		char buf[256];
		switch (f->type) {
		case ORG_TLV_UINT8:
			if (pos + 1 <= datalen) {
				snprintf(buf, sizeof(buf), "%u", data[pos]);
				tag_datatag(w, "value", def->name, buf);
			}
			return;
		case ORG_TLV_UINT16:
			if (pos + 2 <= datalen) {
				uint16_t v =
				    ((uint16_t)data[pos] << 8) | data[pos + 1];
				snprintf(buf, sizeof(buf), "%u", v);
				tag_datatag(w, "value", def->name, buf);
			}
			return;
		case ORG_TLV_UINT32:
			if (pos + 4 <= datalen) {
				uint32_t v =
				    ((uint32_t)data[pos] << 24) |
				    ((uint32_t)data[pos + 1] << 16) |
				    ((uint32_t)data[pos + 2] << 8) |
				    data[pos + 3];
				snprintf(buf, sizeof(buf), "%u", v);
				tag_datatag(w, "value", def->name, buf);
			}
			return;
		case ORG_TLV_STRING: {
			int slen = datalen - pos;
			if (slen > (int)(sizeof(buf) - 1))
				slen = sizeof(buf) - 1;
			if (slen > 0) {
				memcpy(buf, data + pos, slen);
				buf[slen] = '\0';
				tag_datatag(w, "value", def->name, buf);
			}
			return;
		}
		case ORG_TLV_IPV4:
			if (pos + 4 <= datalen) {
				snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
				    data[pos], data[pos + 1], data[pos + 2],
				    data[pos + 3]);
				tag_datatag(w, "value", def->name, buf);
			}
			return;
		case ORG_TLV_MAC:
			if (pos + 6 <= datalen) {
				snprintf(buf, sizeof(buf),
				    "%02x:%02x:%02x:%02x:%02x:%02x", data[pos],
				    data[pos + 1], data[pos + 2], data[pos + 3],
				    data[pos + 4], data[pos + 5]);
				tag_datatag(w, "value", def->name, buf);
			}
			return;
		case ORG_TLV_HEX: {
			size_t slen = 0;
			for (int i = pos; i < datalen && slen < sizeof(buf) - 3;
			     i++)
				slen += snprintf(buf + slen, sizeof(buf) - slen,
				    "%s%02X", (i > pos) ? "," : "", data[i]);
			tag_datatag(w, "value", def->name, buf);
			return;
		}
		}
		return;
	}

	/* Multiple fields or named fields: wrap in a container tag */
	tag_start(w, "org-tlv", def->name);
	struct org_tlv_field *f;
	for (f = def->fields; f && pos < datalen; f = f->next) {
		char buf[256];
		const char *label = f->name ? f->name : def->name;
		const char *tag = f->name ? f->name : "value";

		switch (f->type) {
		case ORG_TLV_UINT8:
			if (pos + 1 > datalen) goto done;
			snprintf(buf, sizeof(buf), "%u", data[pos]);
			tag_datatag(w, tag, label, buf);
			pos += 1;
			break;
		case ORG_TLV_UINT16:
			if (pos + 2 > datalen) goto done;
			{
				uint16_t v = ((uint16_t)data[pos] << 8) |
				    data[pos + 1];
				snprintf(buf, sizeof(buf), "%u", v);
				tag_datatag(w, tag, label, buf);
			}
			pos += 2;
			break;
		case ORG_TLV_UINT32:
			if (pos + 4 > datalen) goto done;
			{
				uint32_t v =
				    ((uint32_t)data[pos] << 24) |
				    ((uint32_t)data[pos + 1] << 16) |
				    ((uint32_t)data[pos + 2] << 8) |
				    data[pos + 3];
				snprintf(buf, sizeof(buf), "%u", v);
				tag_datatag(w, tag, label, buf);
			}
			pos += 4;
			break;
		case ORG_TLV_STRING: {
			int slen = datalen - pos;
			if (slen > (int)(sizeof(buf) - 1))
				slen = sizeof(buf) - 1;
			if (slen > 0) {
				memcpy(buf, data + pos, slen);
				buf[slen] = '\0';
				tag_datatag(w, tag, label, buf);
			}
			pos = datalen;
			break;
		}
		case ORG_TLV_IPV4:
			if (pos + 4 > datalen) goto done;
			snprintf(buf, sizeof(buf), "%u.%u.%u.%u", data[pos],
			    data[pos + 1], data[pos + 2], data[pos + 3]);
			tag_datatag(w, tag, label, buf);
			pos += 4;
			break;
		case ORG_TLV_MAC:
			if (pos + 6 > datalen) goto done;
			snprintf(buf, sizeof(buf),
			    "%02x:%02x:%02x:%02x:%02x:%02x", data[pos],
			    data[pos + 1], data[pos + 2], data[pos + 3],
			    data[pos + 4], data[pos + 5]);
			tag_datatag(w, tag, label, buf);
			pos += 6;
			break;
		case ORG_TLV_HEX: {
			size_t slen = 0;
			for (int i = pos; i < datalen && slen < sizeof(buf) - 3;
			     i++)
				slen += snprintf(buf + slen, sizeof(buf) - slen,
				    "%s%02X", (i > pos) ? "," : "", data[i]);
			tag_datatag(w, tag, label, buf);
			pos = datalen;
			break;
		}
		}
	}

	/* Remaining bytes as hex */
	if (pos < datalen) {
		char buf[1600];
		size_t slen = 0;
		for (int i = pos; i < datalen && slen < sizeof(buf) - 3; i++)
			slen += snprintf(buf + slen, sizeof(buf) - slen, "%s%02X",
			    (i > pos) ? "," : "", data[i]);
		tag_datatag(w, "extra", "Extra bytes", buf);
	}

done:
	tag_end(w);
}

static void
free_fields(struct org_tlv_field *f)
{
	while (f) {
		struct org_tlv_field *next = f->next;
		free(f->name);
		free(f);
		f = next;
	}
}

void
org_tlv_conf_free(void)
{
	while (def_list) {
		struct org_tlv_def *next = def_list->next;
		free(def_list->name);
		free_fields(def_list->fields);
		free(def_list);
		def_list = next;
	}
	while (vendor_list) {
		struct org_tlv_vendor *next = vendor_list->next;
		free(vendor_list->vendor_name);
		free(vendor_list);
		vendor_list = next;
	}
}
