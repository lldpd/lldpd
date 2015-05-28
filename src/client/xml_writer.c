/* -*- mode: c; c-file-style: "openbsd" -*- */
/*
 * Copyright (c) 2010 Andreas Hofmeister <andi@collax.com>
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

#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdocumentation"
#endif
#include <libxml/encoding.h>
#include <libxml/xmlwriter.h>
#if defined(__clang__)
#pragma clang diagnostic pop
#endif

#include "writer.h"
#include "../log.h"

struct xml_writer_private {
	xmlTextWriterPtr xw;
	xmlDocPtr doc;
};

void xml_start(struct writer * w , const char * tag, const char * descr ) {
	struct xml_writer_private * p = w->priv;

	if (xmlTextWriterStartElement(p->xw, BAD_CAST tag) < 0)
		log_warnx("lldpctl", "cannot start '%s' element", tag);

	if ( descr && (strlen(descr) > 0) ) {
		if (xmlTextWriterWriteFormatAttribute(p->xw, BAD_CAST "label", "%s", descr) < 0)
			log_warnx("lldpctl", "cannot add attribute 'label' to element %s", tag);
	}
}

void xml_attr(struct writer * w, const char * tag, const char * descr, const char * value ) {
	struct xml_writer_private * p = w->priv;

	if (xmlTextWriterWriteFormatAttribute(p->xw, BAD_CAST tag, "%s", value) < 0)
		log_warnx("lldpctl", "cannot add attribute %s with value %s", tag, value);
}

void xml_data(struct writer * w, const char * data) {
	struct xml_writer_private * p = w->priv;
	if (xmlTextWriterWriteString(p->xw, BAD_CAST data) < 0 )
		log_warnx("lldpctl", "cannot add '%s' as data to element", data);
}

void xml_end(struct writer * w) {
	struct xml_writer_private * p = w->priv;

	if (xmlTextWriterEndElement(p->xw) < 0 )
		log_warnx("lldpctl", "cannot end element");
}

#define MY_ENCODING "UTF-8"

void xml_finish(struct writer * w) {
	struct xml_writer_private * p = w->priv;
	int failed = 0;

	if (xmlTextWriterEndDocument(p->xw) < 0 ) {
		log_warnx("lldpctl", "cannot finish document");
		failed = 1;
	}

	xmlFreeTextWriter(p->xw);
	
	if ( ! failed )
		xmlSaveFileEnc("-", p->doc, MY_ENCODING);

	xmlFreeDoc(p->doc);

	free( w->priv );
	free( w );
}

struct writer * xml_init(FILE * fh) {

	struct writer * result;
	struct xml_writer_private * priv;

	priv = malloc( sizeof( *priv ) );
	if ( ! priv ) {
		fatalx("lldpctl", "out of memory");
		return NULL;
	}

	priv->xw = xmlNewTextWriterDoc(&(priv->doc), 0);
	if ( ! priv->xw ) {
		fatalx("lldpctl", "cannot create xml writer");
		return NULL;
	}

	xmlTextWriterSetIndent(priv->xw, 4);

	if (xmlTextWriterStartDocument(priv->xw, NULL, MY_ENCODING, NULL) < 0 ) {
		fatalx("lldpctl", "cannot start xml document");
		return NULL;
	}

	result = malloc( sizeof( struct writer ) );
	if ( ! result ) {
		fatalx("lldpctl", "out of memory");
		return NULL;
	}

	result->priv  = priv;
	result->start = xml_start;
	result->attr  = xml_attr;
	result->data  = xml_data;
	result->end   = xml_end;
	result->finish= xml_finish;

	return result;
}

