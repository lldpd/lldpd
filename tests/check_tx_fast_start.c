/* -*- mode: c; c-file-style: "openbsd" -*- */
/*
 * Copyright (c) 2026
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted.
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
#include <event2/event.h>
#include <net/if.h>
#include <stdio.h>

#include "../src/daemon/lldpd.h"

static struct lldpd cfg;
static struct lldpd_chassis chassis;
static struct lldpd_hardware ports[2];
static int sends;
static int frames;
static char last_frame[1500];
static size_t last_frame_length;
static unsigned char neighbor_id, revision;
#ifdef ENABLE_DOT3
static int pse_allocated;
#  ifdef ENABLE_CDP
static int pse_management_id;
#  endif
#endif

static void
init_port_lists(struct lldpd_port *port)
{
#ifdef ENABLE_DOT1
	TAILQ_INIT(&port->p_vlans);
	TAILQ_INIT(&port->p_ppvids);
	TAILQ_INIT(&port->p_pids);
#endif
#ifdef ENABLE_CUSTOM
	TAILQ_INIT(&port->p_custom_list);
#endif
}

static int
receive_packet(struct lldpd *unused, struct lldpd_hardware *hardware, int fd,
    char *buffer, size_t length)
{
	ck_assert(length >= 64);
	memset(buffer, 0, 64);
	buffer[14] = neighbor_id;
	buffer[15] = revision;
	return 64;
}

static int
guess_packet(char *buffer, int length)
{
	return 1;
}

static int
decode_packet(struct lldpd *unused, char *buffer, int length,
    struct lldpd_hardware *hardware, struct lldpd_chassis **remote_chassis,
    struct lldpd_port **remote_port)
{
	struct lldpd_chassis *c = calloc(1, sizeof(*c));
	struct lldpd_port *p = calloc(1, sizeof(*p));
	ck_assert(c != NULL);
	ck_assert(p != NULL);
	TAILQ_INIT(&c->c_mgmt);
	init_port_lists(p);
	c->c_id = malloc(1);
	p->p_id = malloc(1);
	ck_assert(c->c_id != NULL);
	ck_assert(p->p_id != NULL);
	c->c_id[0] = buffer[14];
	p->p_id[0] = 'p';
	c->c_id_len = p->p_id_len = 1;
	c->c_id_subtype = LLDP_CHASSISID_SUBTYPE_LOCAL;
	p->p_id_subtype = LLDP_PORTID_SUBTYPE_LOCAL;
	p->p_ttl = 120;
#ifdef ENABLE_DOT3
	p->p_power.devicetype = LLDP_DOT3_POWER_PSE;
	p->p_power.allocated = pse_allocated;
#  ifdef ENABLE_CDP
	p->p_cdp_power.management_id = pse_management_id;
#  endif
#endif
	*remote_chassis = c;
	*remote_port = p;
	return 0;
}

static int
send_frame(struct lldpd *unused, struct lldpd_hardware *hardware, char *buffer,
    size_t length)
{
	ck_assert(length <= sizeof(last_frame));
	memcpy(last_frame, buffer, length);
	last_frame_length = length;
	frames++;
	return 0;
}

static struct lldpd_ops ops = { .send = send_frame, .recv = receive_packet };

static int
send_packet(struct lldpd *unused, struct lldpd_hardware *hardware)
{
	sends++;
	return 0;
}

static struct protocol protocols[] = { { .mode = LLDPD_MODE_LLDP,
					   .enabled = 2,
					   .name = "LLDP",
					   .send = send_packet,
					   .decode = decode_packet,
					   .guess = guess_packet },
	{ 0 } };

static void
setup(void)
{
	int i;

	memset(&cfg, 0, sizeof(cfg));
	memset(&chassis, 0, sizeof(chassis));
	memset(ports, 0, sizeof(ports));
	sends = 0;
	frames = 0;
	last_frame_length = 0;
	neighbor_id = 1;
	revision = 1;
#ifdef ENABLE_DOT3
	pse_allocated = 1;
#  ifdef ENABLE_CDP
	pse_management_id = 1;
#  endif
#endif
	TAILQ_INIT(&cfg.g_chassis);
	TAILQ_INIT(&cfg.g_hardware);
	TAILQ_INIT(&chassis.c_mgmt);
	TAILQ_INSERT_TAIL(&cfg.g_chassis, &chassis, c_entries);
	cfg.g_base = event_base_new();
	ck_assert(cfg.g_base != NULL);
	cfg.g_protocols = protocols;
	cfg.g_config.c_enable_fast_start = 1;
	cfg.g_config.c_tx_fast_init = 4;
	cfg.g_config.c_tx_fast_interval = 2;
	cfg.g_config.c_tx_interval = 30000;
	cfg.g_config.c_tx_hold = 4;
	cfg.g_config.c_ttl = 120;
	for (i = 0; i < 2; i++) {
		struct lldpd_hardware *port = &ports[i];
		port->h_cfg = &cfg;
		port->h_flags = IFF_RUNNING;
		port->h_ops = &ops;
		port->h_mtu = 1500;
		port->h_ifindex = i + 1;
		snprintf(port->h_ifname, sizeof(port->h_ifname), "test%d", i);
		TAILQ_INIT(&port->h_rports);
		port->h_lport.p_chassis = &chassis;
		init_port_lists(&port->h_lport);
		TAILQ_INSERT_TAIL(&cfg.g_hardware, port, h_entries);
	}
}

static void
teardown(void)
{
	int i;
	for (i = 0; i < 2; i++) {
		if (ports[i].h_timer) event_free(ports[i].h_timer);
		free(ports[i].h_lport_previous);
		free(ports[i].h_lchassis_previous_id);
		free(ports[i].h_lport_previous_id);
		lldpd_remote_cleanup(&ports[i], NULL, 1);
		ports[i].h_lport.p_chassis = NULL;
		lldpd_port_cleanup(&ports[i].h_lport, 1);
	}
	while (TAILQ_NEXT(&chassis, c_entries)) {
		struct lldpd_chassis *remote = TAILQ_NEXT(&chassis, c_entries);
		TAILQ_REMOVE(&cfg.g_chassis, remote, c_entries);
		lldpd_chassis_cleanup(remote, 1);
	}
	free(cfg.g_chassis_previous);
	lldpd_chassis_cleanup(&chassis, 0);
	lldpd_config_cleanup(&cfg.g_config);
	event_base_free(cfg.g_base);
}

static int
pending(struct lldpd_hardware *port)
{
	return port->h_timer && event_pending(port->h_timer, EV_TIMEOUT, NULL);
}

static void
clear_timer(struct lldpd_hardware *port)
{
	if (port->h_timer) event_del(port->h_timer);
	port->h_tx_fast = 0;
}

static void
assert_interval(struct lldpd_hardware *port, int seconds)
{
	struct timeval expires, now;
	long remaining;
	ck_assert(event_pending(port->h_timer, EV_TIMEOUT, &expires) != 0);
	ck_assert_int_eq(event_base_gettimeofday_cached(cfg.g_base, &now), 0);
	remaining =
	    (expires.tv_sec - now.tv_sec) * 1000000L + expires.tv_usec - now.tv_usec;
	ck_assert_msg(remaining > (seconds - 1) * 1000000L &&
		remaining <= (seconds + 1) * 1000000L,
	    "unexpected remaining interval: %ld microseconds", remaining);
}

static void
fire_timer(struct lldpd_hardware *port)
{
	event_active(port->h_timer, EV_TIMEOUT, 1);
	ck_assert_int_eq(event_base_loop(cfg.g_base, EVLOOP_ONCE | EVLOOP_NONBLOCK), 0);
}

START_TEST(test_burst_and_restart)
{
	int i;
	cfg.g_config.c_tx_fast_init = 3;
	lldpd_set_local_change(&ports[0], "test");
	ck_assert_int_eq(ports[0].h_tx_fast, 3);
	ck_assert(pending(&ports[0]));
	assert_interval(&ports[0], 0);
	ck_assert(!pending(&ports[1]));
	fire_timer(&ports[0]);
	ck_assert_int_eq(sends, 1);
	ck_assert_int_eq(ports[0].h_tx_fast, 2);
	assert_interval(&ports[0], 2);
	lldpd_set_local_change(&ports[0], "restart");
	ck_assert_int_eq(ports[0].h_tx_fast, 3);
	for (i = 2; i >= 0; i--) {
		fire_timer(&ports[0]);
		ck_assert_int_eq(ports[0].h_tx_fast, i);
		assert_interval(&ports[0], i ? 2 : 30);
	}
	ck_assert_int_eq(sends, 4);
}
END_TEST

START_TEST(test_tx_disable_shutdown)
{
	struct lldpd_chassis *decoded_chassis = NULL;
	struct lldpd_port *decoded_port = NULL;
	chassis.c_id_subtype = LLDP_CHASSISID_SUBTYPE_LOCAL;
	chassis.c_id = strdup("chassis");
	chassis.c_id_len = strlen(chassis.c_id);
	ports[0].h_lport.p_id_subtype = LLDP_PORTID_SUBTYPE_LOCAL;
	ports[0].h_lport.p_id = strdup("port");
	ports[0].h_lport.p_id_len = strlen(ports[0].h_lport.p_id);
	lldpd_reset_timer(&cfg);
	clear_timer(&ports[0]);
	clear_timer(&ports[1]);
	ck_assert_int_eq(lldp_send(&cfg, &ports[0]), 0);
	ck_assert_int_eq(frames, 1);
	ports[0].h_lport.p_disable_tx = 1;
	lldpd_reset_timer(&cfg);
	ck_assert_int_eq(frames, 2);
	ck_assert_int_eq(lldp_decode(&cfg, last_frame, last_frame_length, &ports[0],
			     &decoded_chassis, &decoded_port),
	    1);
	ck_assert_int_eq(decoded_port->p_ttl, 0);
	lldpd_port_cleanup(decoded_port, 1);
	free(decoded_port);
	lldpd_chassis_cleanup(decoded_chassis, 1);
}
END_TEST

START_TEST(test_new_neighbor_fast_start_is_per_port)
{
	ck_assert_int_eq(ports[0].h_tx_fast, 0);
	ck_assert_int_eq(ports[1].h_tx_fast, 0);
	lldpd_recv(&cfg, &ports[0], -1);
	ck_assert_int_eq(ports[0].h_tx_fast, cfg.g_config.c_tx_fast_init);
	ck_assert_int_eq(ports[1].h_tx_fast, 0);
	ck_assert(pending(&ports[0]));
	ck_assert(!pending(&ports[1]));
}
END_TEST

START_TEST(test_neighbors)
{
	lldpd_recv(&cfg, &ports[0], -1);
	clear_timer(&ports[0]);
	lldpd_recv(&cfg, &ports[0], -1);
	ck_assert(!pending(&ports[0]));
	revision++;
	lldpd_recv(&cfg, &ports[0], -1);
	ck_assert(!pending(&ports[0]));
	ports[0].h_tx_fast = 2;
	neighbor_id++;
	lldpd_recv(&cfg, &ports[0], -1);
	ck_assert_int_eq(ports[0].h_tx_fast, 2);
	ck_assert(pending(&ports[0]));
	clear_timer(&ports[0]);
	cfg.g_config.c_enable_fast_start = 0;
	neighbor_id++;
	lldpd_recv(&cfg, &ports[0], -1);
	ck_assert_int_eq(ports[0].h_tx_fast, 0);
	ck_assert(pending(&ports[0]));
}
END_TEST

#ifdef ENABLE_DOT3
START_TEST(test_received_power_change)
{
	ports[0].h_lport.p_power.devicetype = LLDP_DOT3_POWER_PD;
	lldpd_recv(&cfg, &ports[0], -1);
	ck_assert_int_eq(ports[0].h_lport.p_power.allocated, 1);
	clear_timer(&ports[0]);
	ports[0].h_tx_fast = 2;
	revision = 2;
	pse_allocated = 2;
	lldpd_recv(&cfg, &ports[0], -1);
	ck_assert_int_eq(ports[0].h_lport.p_power.allocated, 2);
	ck_assert_int_eq(ports[0].h_tx_fast, 4);
	ck_assert(pending(&ports[0]));
	ck_assert(!pending(&ports[1]));
}
END_TEST

#  ifdef ENABLE_CDP
START_TEST(test_received_cdp_power_management_change)
{
	ports[0].h_lport.p_power.devicetype = LLDP_DOT3_POWER_PD;
	lldpd_recv(&cfg, &ports[0], -1);
	ck_assert_int_eq(ports[0].h_lport.p_cdp_power.management_id, 1);
	clear_timer(&ports[0]);
	ports[0].h_tx_fast = 2;
	revision = 2;
	pse_management_id = 2;
	lldpd_recv(&cfg, &ports[0], -1);
	ck_assert_int_eq(ports[0].h_lport.p_power.allocated, 1);
	ck_assert_int_eq(ports[0].h_lport.p_cdp_power.management_id, 2);
	ck_assert_int_eq(ports[0].h_tx_fast, 4);
	ck_assert(pending(&ports[0]));
	ck_assert(!pending(&ports[1]));
}
END_TEST
#  endif
#endif

START_TEST(test_disabled)
{
	cfg.g_config.c_enable_fast_start = 0;
	ports[0].h_tx_fast = 2;
	lldpd_set_local_change(&ports[0], "test");
	ck_assert_int_eq(ports[0].h_tx_fast, 2);
	ck_assert(pending(&ports[0]));
	clear_timer(&ports[0]);
	lldpd_set_local_change(&ports[0], "test");
	fire_timer(&ports[0]);
	ck_assert_int_eq(ports[0].h_tx_fast, 0);
	assert_interval(&ports[0], 30);
}
END_TEST

START_TEST(test_port_snapshots)
{
	lldpd_reset_timer(&cfg);
	ck_assert_int_eq(ports[0].h_tx_fast, 4);
	ck_assert_int_eq(ports[1].h_tx_fast, 4);
	clear_timer(&ports[0]);
	clear_timer(&ports[1]);
	lldpd_reset_timer(&cfg);
	ck_assert(!pending(&ports[0]));
	ck_assert(!pending(&ports[1]));
	ports[0].h_lport.p_descr = strdup("changed");
	lldpd_reset_timer(&cfg);
	ck_assert_int_eq(ports[0].h_tx_fast, 4);
	ck_assert(pending(&ports[0]));
	ck_assert(!pending(&ports[1]));
	clear_timer(&ports[0]);
	ports[1].h_ifindex_changed = 1;
	lldpd_reset_timer(&cfg);
	ck_assert(!pending(&ports[0]));
	ck_assert_int_eq(ports[1].h_tx_fast, 4);
	ck_assert(pending(&ports[1]));
	ck_assert_int_eq(ports[1].h_ifindex_changed, 0);
	clear_timer(&ports[1]);
	ports[1].h_lport.p_disable_tx = 1;
	lldpd_reset_timer(&cfg);
	clear_timer(&ports[1]);
	ports[1].h_lport.p_disable_tx = 0;
	lldpd_reset_timer(&cfg);
	ck_assert_int_eq(ports[1].h_tx_fast, 4);
	ck_assert(pending(&ports[1]));
	ck_assert(!pending(&ports[0]));
}
END_TEST

START_TEST(test_chassis_snapshots)
{
	struct in_addr address = { .s_addr = htonl(0xc0000201) };
	struct lldpd_mgmt *mgmt;
	chassis.c_name = strdup("first");
	lldpd_check_chassis_change(&cfg);
	ck_assert_int_eq(ports[0].h_tx_fast, 4);
	ck_assert_int_eq(ports[1].h_tx_fast, 4);
	clear_timer(&ports[0]);
	clear_timer(&ports[1]);
	lldpd_check_chassis_change(&cfg);
	ck_assert(!pending(&ports[0]));
	ck_assert(!pending(&ports[1]));
	free(chassis.c_name);
	chassis.c_name = strdup("other");
	lldpd_check_chassis_change(&cfg);
	ck_assert(pending(&ports[0]));
	ck_assert(pending(&ports[1]));
	clear_timer(&ports[0]);
	clear_timer(&ports[1]);
	free(chassis.c_name);
	chassis.c_name = strdup("a longer name");
	lldpd_check_chassis_change(&cfg);
	ck_assert_int_eq(ports[0].h_tx_fast, 4);
	ck_assert_int_eq(ports[1].h_tx_fast, 4);
	ck_assert(pending(&ports[0]));
	ck_assert(pending(&ports[1]));
	clear_timer(&ports[0]);
	clear_timer(&ports[1]);
	cfg.g_config.c_enable_fast_start = 0;
	chassis.c_cap_enabled = LLDP_CAP_ROUTER;
	mgmt = lldpd_alloc_mgmt(LLDPD_AF_IPV4, &address, sizeof(address), 1);
	ck_assert(mgmt != NULL);
	TAILQ_INSERT_TAIL(&chassis.c_mgmt, mgmt, m_entries);
	lldpd_check_chassis_change(&cfg);
	ck_assert_int_eq(ports[0].h_tx_fast, 0);
	ck_assert_int_eq(ports[1].h_tx_fast, 0);
	ck_assert(pending(&ports[0]));
	ck_assert(pending(&ports[1]));
}
END_TEST

static ssize_t
capture_reply(void *out, int type, void *buffer, size_t length)
{
	*(int *)out = type;
	return length;
}

static int
set_config(struct lldpd_config *config)
{
	void *buffer = NULL;
	ssize_t length = lldpd_config_serialize(config, &buffer);
	int type = NONE, subscribed = 0;
	ck_assert(length > 0);
	ck_assert(client_handle_client(&cfg, capture_reply, &type, SET_CONFIG, buffer,
		      length, &subscribed) >= 0);
	free(buffer);
	return type;
}

START_TEST(test_configuration_changes)
{
	struct lldpd_config config = cfg.g_config;
	config.c_tx_hold = 5;
	ck_assert_int_eq(set_config(&config), SET_CONFIG);
	ck_assert_int_eq(ports[0].h_tx_fast, 4);
	ck_assert_int_eq(ports[1].h_tx_fast, 4);
	ck_assert(pending(&ports[0]));
	ck_assert(pending(&ports[1]));
	clear_timer(&ports[0]);
	clear_timer(&ports[1]);
	config = cfg.g_config;
	ck_assert_int_eq(set_config(&config), SET_CONFIG);
	ck_assert(!pending(&ports[0]));
	ck_assert(!pending(&ports[1]));
	config.c_cap_advertise = 1;
	ck_assert_int_eq(set_config(&config), SET_CONFIG);
	ck_assert(pending(&ports[0]));
	ck_assert(pending(&ports[1]));
	ck_assert_int_eq(ports[0].h_tx_fast, 4);
	ck_assert_int_eq(ports[1].h_tx_fast, 4);
}
END_TEST

START_TEST(test_configuration_variants)
{
	struct lldpd_config config;
	int i;

	cfg.g_config.c_hostname = strdup("initial");
	cfg.g_config.c_cap_override = 1;
	for (i = 0; i < 11; i++) {
		config = cfg.g_config;
		switch (i) {
		case 0:
			config.c_tx_interval = 25000;
			break;
		case 1:
			config.c_lldp_portid_type = LLDP_PORTID_SUBTYPE_IFNAME;
			break;
		case 2:
			config.c_lldp_agent_type = LLDP_AGENT_TYPE_NEAREST_BRIDGE;
			break;
		case 3:
			config.c_lldp_portdescr_type = LLDP_PORTDESCR_SRC_ALIAS;
			break;
		case 4:
			config.c_hostname = "changed";
			break;
		case 5:
			config.c_description = "changed";
			break;
		case 6:
			config.c_cid_string = "new-chassis-id";
			break;
		case 7:
			config.c_platform = "new-platform";
			break;
		case 8:
			config.c_cap_advertise = 1;
			break;
		case 9:
			config.c_mgmt_advertise = 1;
			break;
		case 10:
			config.c_cap_override = 0;
			break;
		}
		ck_assert_int_eq(set_config(&config), SET_CONFIG);
		ck_assert_int_eq(ports[0].h_tx_fast, 4);
		ck_assert_int_eq(ports[1].h_tx_fast, 4);
		ck_assert(pending(&ports[0]));
		ck_assert(pending(&ports[1]));
		clear_timer(&ports[0]);
		clear_timer(&ports[1]);
	}
	cfg.g_config.c_enable_fast_start = 0;
	config = cfg.g_config;
	config.c_tx_hold = 5;
	ck_assert_int_eq(set_config(&config), SET_CONFIG);
	ck_assert_int_eq(ports[0].h_tx_fast, 0);
	ck_assert_int_eq(ports[1].h_tx_fast, 0);
	ck_assert(pending(&ports[0]));
	ck_assert(pending(&ports[1]));
	clear_timer(&ports[0]);
	clear_timer(&ports[1]);
	config = cfg.g_config;
	config.c_tx_hold = 101;
	ck_assert_int_eq(set_config(&config), SET_CONFIG);
	ck_assert_int_eq(cfg.g_config.c_tx_hold, 5);
	ck_assert(!pending(&ports[0]));
	ck_assert(!pending(&ports[1]));
}
END_TEST

START_TEST(test_port_configuration)
{
	struct lldpd_port_set set = { .ifname = "test0",
		.local_descr = "new",
		.vlan_tx_enabled = -1 };
	void *buffer = NULL;
	int type = NONE, subscribed = 0;
	ssize_t length = lldpd_port_set_serialize(&set, &buffer);
	ck_assert(length > 0);
	ck_assert(client_handle_client(&cfg, capture_reply, &type, SET_PORT, buffer,
		      length, &subscribed) >= 0);
	free(buffer);
	ck_assert_int_eq(type, SET_PORT);
	ck_assert_int_eq(ports[0].h_tx_fast, 4);
	ck_assert(pending(&ports[0]));
	ck_assert(!pending(&ports[1]));
	clear_timer(&ports[0]);
	cfg.g_config.c_enable_fast_start = 0;
	set.local_descr = "another";
	buffer = NULL;
	length = lldpd_port_set_serialize(&set, &buffer);
	ck_assert(length > 0);
	ck_assert(client_handle_client(&cfg, capture_reply, &type, SET_PORT, buffer,
		      length, &subscribed) >= 0);
	free(buffer);
	ck_assert_int_eq(type, SET_PORT);
	ck_assert_int_eq(ports[0].h_tx_fast, 0);
	ck_assert(pending(&ports[0]));
	ck_assert(!pending(&ports[1]));
	clear_timer(&ports[0]);
	set.ifname = "missing";
	buffer = NULL;
	length = lldpd_port_set_serialize(&set, &buffer);
	ck_assert(length > 0);
	ck_assert(client_handle_client(&cfg, capture_reply, &type, SET_PORT, buffer,
		      length, &subscribed) >= 0);
	free(buffer);
	ck_assert_int_eq(type, NONE);
	ck_assert(!pending(&ports[0]));
	ck_assert(!pending(&ports[1]));
}
END_TEST

int
main(void)
{
	int failures;
	Suite *suite = suite_create("TX fast start");
	TCase *tc = tcase_create("Behavior");
	SRunner *runner;
	tcase_add_checked_fixture(tc, setup, teardown);
	tcase_add_test(tc, test_burst_and_restart);
	tcase_add_test(tc, test_disabled);
	tcase_add_test(tc, test_port_snapshots);
	tcase_add_test(tc, test_tx_disable_shutdown);
	tcase_add_test(tc, test_chassis_snapshots);
	tcase_add_test(tc, test_configuration_changes);
	tcase_add_test(tc, test_configuration_variants);
	tcase_add_test(tc, test_port_configuration);
	tcase_add_test(tc, test_new_neighbor_fast_start_is_per_port);
	tcase_add_test(tc, test_neighbors);
#ifdef ENABLE_DOT3
	tcase_add_test(tc, test_received_power_change);
#  ifdef ENABLE_CDP
	tcase_add_test(tc, test_received_cdp_power_management_change);
#  endif
#endif
	suite_add_tcase(suite, tc);
	runner = srunner_create(suite);
	srunner_run_all(runner, CK_ENV);
	failures = srunner_ntests_failed(runner);
	srunner_free(runner);
	return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
