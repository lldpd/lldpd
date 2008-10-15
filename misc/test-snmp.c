/* gcc -Wall $(net-snmp-config --base-cflags) test-snmp.c $(net-snmp-config --agent-libs) -o test-snmp */

#include <sys/queue.h>

#define USING_AGENTX_SUBAGENT_MODULE 1

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/agent/snmp_vars.h>

#include "../lldp.h"

typedef struct lldpGlobal {
  int32_t messageTxInterval;
  int32_t messageTxHoldMultiplier;
  int32_t reinitDelay;
  int32_t txDelay;
  int32_t notificationInterval;
} lldpGlobal;

struct lldpGlobal global = {
  .messageTxInterval = 30,
  .messageTxHoldMultiplier = 4,
  .reinitDelay = 2,
  .txDelay = 5,
  .notificationInterval = 5
};

oid messageTxInterval_oid[] = {1, 0, 8802, 1, 1, 2, 1, 1, 1, 0};
oid messageTxHoldMultiplier_oid[] = {1, 0, 8802, 1, 1, 2, 1, 1, 2, 0};
oid reinitDelay_oid[] = {1, 0, 8802, 1, 1, 2, 1, 1, 3, 0};
oid txDelay_oid[] = {1, 0, 8802, 1, 1, 2, 1, 1, 4, 0};
oid notificationInterval_oid[] = {1, 0, 8802, 1, 1, 2, 1, 1, 5, 0};

typedef struct lldpStats {
  u_int32_t lastChangeTime;
  u_int32_t inserts;
  u_int32_t deletes;
  u_int32_t drops;
  u_int32_t ageouts;
} lldpStats;

struct lldpStats stats = {
  .lastChangeTime = 4575120,
  .inserts = 1451,
  .deletes = 12,
  .drops = 0,
  .ageouts = 2
};

oid lastChangeTime_oid[] = {1, 0, 8802, 1, 1, 2, 1, 2, 1, 0};
oid inserts_oid[] = {1, 0, 8802, 1, 1, 2, 1, 2, 2, 0};
oid deletes_oid[] = {1, 0, 8802, 1, 1, 2, 1, 2, 3, 0};
oid drops_oid[] = {1, 0, 8802, 1, 1, 2, 1, 2, 4, 0};
oid ageouts_oid[] = {1, 0, 8802, 1, 1, 2, 1, 2, 5, 0};

typedef struct lldpChassis {
  int chassisIdSubtype;
  u_int8_t chassisId[256];
  int chassisId_len;
  char sysName[256];
  char sysDesc[256];
  u_int8_t sysCapSupported;
  u_int8_t sysCapEnabled;
} lldpChassis;

struct lldpChassis local = {
  .chassisIdSubtype = LLDP_CHASSISID_SUBTYPE_LLADDR,
  .chassisId = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05 },
  .chassisId_len = 6,
  .sysName = "neo.luffy.cx",
  .sysDesc = "Linux neo 2.6.25-2-amd64 #1 SMP Thu Jun 12 15:38:32 UTC 2008 x86_64 GNU/Linux",
  .sysCapSupported = LLDP_CAP_BRIDGE | LLDP_CAP_WLAN | LLDP_CAP_ROUTER,
  .sysCapEnabled = LLDP_CAP_ROUTER
};

oid chassisIdSubtype_oid[] = {1, 0, 8802, 1, 1, 2, 1, 3, 1, 0};
oid chassisId_oid[] = {1, 0, 8802, 1, 1, 2, 1, 3, 2, 0};
oid sysName_oid[] = {1, 0, 8802, 1, 1, 2, 1, 3, 3, 0};
oid sysDesc_oid[] = {1, 0, 8802, 1, 1, 2, 1, 3, 4, 0};
oid sysCapSupported_oid[] = {1, 0, 8802, 1, 1, 2, 1, 3, 5, 0};
oid sysCapEnabled_oid[] = {1, 0, 8802, 1, 1, 2, 1, 3, 6, 0};

typedef struct snmp_type {
  u_char *value;
  int *value_size;
  int type;
} snmp_type;

struct lldpPort {
  int portIdSubtype;
  u_int8_t portId[256];
  int portId_len;
  char portDesc[256];
} lldpPort;

struct lldpRemote {
  /* Index values */
  u_int32_t lldpRemTimeMark;
  int lldpRemLocalPortNum;
  int lldpRemIndex;

  struct lldpPort port;
  struct lldpChassis remote;

  TAILQ_ENTRY(lldpRemote) next;
} lldpRemote;

TAILQ_HEAD(, lldpRemote) r_entries;

struct lldpRemote r1 = {
  .lldpRemTimeMark = 4121,
  .lldpRemLocalPortNum = 1,
  .lldpRemIndex = 1,
  .port = {
    .portIdSubtype = LLDP_PORTID_SUBTYPE_LLADDR,
    .portId = { 0x00, 0x05, 0x06, 0x07, 0x0a, 0x01 },
    .portId_len = 6,
    .portDesc = "eth0"
  },
  .remote = {
    .chassisIdSubtype = LLDP_CHASSISID_SUBTYPE_LLADDR,
    .chassisId = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x06 },
    .chassisId_len = 6,
    .sysName = "titi.luffy.cx",
    .sysDesc = "Linux titi 2.6.25-2-amd64 #1 SMP Thu Jun 12 15:38:32 UTC 2008 x86_64 GNU/Linux",
    .sysCapSupported = LLDP_CAP_BRIDGE | LLDP_CAP_WLAN | LLDP_CAP_ROUTER,
    .sysCapEnabled = LLDP_CAP_ROUTER
  }
};

struct lldpRemote r2 = {
  .lldpRemTimeMark = 4127,
  .lldpRemLocalPortNum = 3,
  .lldpRemIndex = 2,
  .port = {
    .portIdSubtype = LLDP_PORTID_SUBTYPE_LLADDR,
    .portId = { 0x00, 0x05, 0x06, 0x07, 0x0a, 0x03 },
    .portId_len = 6,
    .portDesc = "en4"
  },
  .remote = {
    .chassisIdSubtype = LLDP_CHASSISID_SUBTYPE_LLADDR,
    .chassisId = { 0x07, 0x01, 0x02, 0x03, 0x04, 0x06 },
    .chassisId_len = 6,
    .sysName = "tito.luffy.cx",
    .sysDesc = "Linux tito 2.6.25-2-amd64 #1 SMP Thu Jun 12 15:38:32 UTC 2008 x86_64 GNU/Linux",
    .sysCapSupported = LLDP_CAP_BRIDGE | LLDP_CAP_WLAN | LLDP_CAP_ROUTER,
    .sysCapEnabled = LLDP_CAP_ROUTER
  }
};

int lldpRemTable_handler(
    netsnmp_mib_handler               *handler,
    netsnmp_handler_registration      *reginfo,
    netsnmp_agent_request_info        *reqinfo,
    netsnmp_request_info              *requests) {

  netsnmp_request_info       *request;
  netsnmp_table_request_info *table_info;
  struct lldpRemote          *table_entry;

  switch (reqinfo->mode) {
  case MODE_GET:
    for (request=requests; request; request=request->next) {
      table_entry = (struct lldpRemote *)
	netsnmp_extract_iterator_context(request);
      table_info = netsnmp_extract_table_info(request);

      if (!table_entry) {
	netsnmp_set_request_error(reqinfo, request,
				  SNMP_NOSUCHINSTANCE);
	continue;
      }

      switch (table_info->colnum) {
      case 4:
	snmp_set_var_typed_integer(request->requestvb, ASN_INTEGER,
				   table_entry->remote.chassisIdSubtype);
	break;
      case 5:
	snmp_set_var_typed_value(request->requestvb, ASN_OCTET_STR,
				 (u_char*)table_entry->remote.chassisId,
				 table_entry->remote.chassisId_len);
	break;
      case 6:
	snmp_set_var_typed_integer(request->requestvb, ASN_INTEGER,
				   table_entry->port.portIdSubtype);
	break;
      case 7:
	snmp_set_var_typed_value(request->requestvb, ASN_OCTET_STR,
				 (u_char*)table_entry->port.portId,
				 table_entry->port.portId_len);
	break;
      case 8:
	snmp_set_var_typed_value(request->requestvb, ASN_OCTET_STR,
				 (u_char*)table_entry->port.portDesc,
				 strlen(table_entry->port.portDesc));
	break;
      case 9:
	snmp_set_var_typed_value(request->requestvb, ASN_OCTET_STR,
                                 (u_char*)table_entry->remote.sysName,
				 strlen(table_entry->remote.sysName));
	break;
      case 10:
	snmp_set_var_typed_value(request->requestvb, ASN_OCTET_STR,
				 (u_char*)table_entry->remote.sysDesc,
				 strlen(table_entry->remote.sysDesc));
	break;
      case 11:
	snmp_set_var_typed_value( request->requestvb, ASN_OCTET_STR,
				  (u_char*)&(table_entry->remote.sysCapSupported),
				  1);
	break;
      case 12:
	snmp_set_var_typed_value( request->requestvb, ASN_OCTET_STR,
				  (u_char*)&(table_entry->remote.sysCapEnabled),
				  1);
	break;
      default:
	netsnmp_set_request_error(reqinfo, request,
				  SNMP_NOSUCHOBJECT);
	break;
      }
    }
    break;

  }
  return SNMP_ERR_NOERROR;
}

netsnmp_variable_list *lldpRemTable_get_next_data_point(void **my_loop_context,
                          void **my_data_context,
                          netsnmp_variable_list *put_index_data,
                          netsnmp_iterator_info *mydata) {
  struct lldpRemote *entry = (struct lldpRemote*)*my_loop_context;
  netsnmp_variable_list *idx = put_index_data;

  if (entry) {
    snmp_set_var_typed_integer( idx, ASN_TIMETICKS, entry->lldpRemTimeMark );
    idx = idx->next_variable;
    snmp_set_var_typed_integer( idx, ASN_INTEGER, entry->lldpRemLocalPortNum );
    idx = idx->next_variable;
    snmp_set_var_typed_integer( idx, ASN_INTEGER, entry->lldpRemIndex );
    idx = idx->next_variable;
    *my_data_context = (void *)entry;
    *my_loop_context = TAILQ_NEXT(entry, next);
    return put_index_data;
  } else {
    return NULL;
  }
}

netsnmp_variable_list *lldpRemTable_get_first_data_point(void **my_loop_context,
                          void **my_data_context,
                          netsnmp_variable_list *put_index_data,
                          netsnmp_iterator_info *mydata) {
  *my_loop_context = TAILQ_FIRST(&r_entries);
  return lldpRemTable_get_next_data_point(my_loop_context, my_data_context,
					  put_index_data,  mydata);
}

void populate_r_entries() {
  static oid lldpRemTable_oid[] = {1,0,8802,1,1,2,1,4,1};
  size_t lldpRemTable_oid_len   = OID_LENGTH(lldpRemTable_oid);
  netsnmp_handler_registration    *reg;
  netsnmp_iterator_info           *iinfo;
  netsnmp_table_registration_info *table_info;
  
  reg = netsnmp_create_handler_registration(
					    "lldpRemTable",     lldpRemTable_handler,
					    lldpRemTable_oid, lldpRemTable_oid_len,
					    HANDLER_CAN_RONLY
					    );
  
  table_info = SNMP_MALLOC_TYPEDEF( netsnmp_table_registration_info );
  netsnmp_table_helper_add_indexes(table_info,
				   ASN_TIMETICKS,  /* index: lldpRemTimeMark */
				   ASN_INTEGER,  /* index: lldpRemLocalPortNum */
				   ASN_INTEGER,  /* index: lldpRemIndex */
				   0);
  table_info->min_column = 1;
  table_info->max_column = 12;
  
  iinfo = SNMP_MALLOC_TYPEDEF( netsnmp_iterator_info );
  iinfo->get_first_data_point = lldpRemTable_get_first_data_point;
  iinfo->get_next_data_point  = lldpRemTable_get_next_data_point;
  iinfo->table_reginfo        = table_info;
  
  netsnmp_register_table_iterator( reg, iinfo );
  
  TAILQ_INIT(&r_entries);
  TAILQ_INSERT_TAIL(&r_entries, &r1, next);
  TAILQ_INSERT_TAIL(&r_entries, &r2, next);
}

int netsnmp_instance_universal_handler(netsnmp_mib_handler *handler,
				       netsnmp_handler_registration *reginfo,
				       netsnmp_agent_request_info *reqinfo,
				       netsnmp_request_info *requests) {
    struct snmp_type *st = (struct snmp_type *) handler->myvoid;
    int size;

    switch (reqinfo->mode) {
    case MODE_GET:
      if (st->value_size == NULL) {
	/* Try to guess */
	switch (st->type) {
	case ASN_COUNTER:
	case ASN_TIMETICKS:
	case ASN_INTEGER:
	case ASN_GAUGE:
	  size = 4;
	  break;
	case ASN_OCTET_STR:
	  size = strlen((char*)st->value);
	  break;
	default:
	  size = 1;
	}
      } else
	size = *(st->value_size);
      snmp_set_var_typed_value(requests->requestvb, st->type,
			       st->value, size);
      break;
    default:
        snmp_log(LOG_ERR,
                 "netsnmp_instance_universal_handler: illegal mode\n");
        netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_GENERR);
        return SNMP_ERR_NOERROR;
    }
    if (handler->next && handler->next->access_method)
      return netsnmp_call_next_handler(handler, reginfo, reqinfo,
				       requests);
    return SNMP_ERR_NOERROR;
}

int netsnmp_register_read_only_universal_instance(const char *name,
						  oid * reg_oid,
						  size_t reg_oid_len,
						  void *value,
						  int *value_size,
						  int type) {
  netsnmp_handler_registration *myreg;
  struct snmp_type *st;

  /* We will leak memory... */
  st = (struct snmp_type *)malloc(sizeof(struct snmp_type));
  st->value = value;
  st->value_size = value_size;
  st->type = type;

  myreg =
    netsnmp_create_handler_registration(name,
					netsnmp_instance_universal_handler,
					reg_oid, reg_oid_len,
					HANDLER_CAN_RONLY);
  myreg->handler->myvoid = (void *) st;

  return netsnmp_register_read_only_instance(myreg);
}

#define REGISTER(variable, name, type)			      \
  netsnmp_register_read_only_universal_instance(#name,	      \
				name ## _oid,		      \
				OID_LENGTH(name ## _oid),     \
				&variable.name, NULL, type)

#define REGISTER_S(variable, name, type)		      \
  netsnmp_register_read_only_universal_instance(#name,	      \
				name ## _oid,		      \
				OID_LENGTH(name ## _oid),     \
				&variable.name, &variable.name ## _len, type)

#define REGISTER_FS(variable, name, size, type)		      \
  netsnmp_register_read_only_universal_instance(#name,	      \
				name ## _oid,		      \
				OID_LENGTH(name ## _oid),     \
				&variable.name, &size, type)

int one = 1;
int two = 2;
int three = 3;
int interfaces[] = {1, 2, 3, 4};
char stuff[] = { 0xf0 };

void register_lldpPortConfig() {
  int i;
  static oid lldpPortConfigTable_oid[] = {1,0,8802,1,1,2,1,1,6};
  size_t lldpPortConfigTable_oid_len = OID_LENGTH(lldpPortConfigTable_oid);
  netsnmp_table_data_set *table_set;
  netsnmp_table_row *row;
  table_set = netsnmp_create_table_data_set("lldpPortConfigTable");
  netsnmp_table_set_add_indexes(table_set,
				ASN_INTEGER,
				0);
  netsnmp_table_set_multi_add_default_row(table_set,
					  2, ASN_INTEGER, 0, NULL, 0,
					  3, ASN_INTEGER, 0, NULL, 0,
					  4, ASN_OCTET_STR, 0, NULL, 0,
					  0);
  netsnmp_register_table_data_set(
     netsnmp_create_handler_registration("lldpPortConfigTable", NULL,
					 lldpPortConfigTable_oid,
					 lldpPortConfigTable_oid_len,
					 HANDLER_CAN_RONLY),
     table_set, NULL);
  for (i=0; i < sizeof(interfaces)/sizeof(int); i++) {
    row = netsnmp_create_table_data_row();
    netsnmp_table_row_add_index(row, ASN_INTEGER, (u_char*)(&interfaces[i]), sizeof(int));
    netsnmp_set_row_column(row, 2, ASN_INTEGER, (char*)&three, sizeof(three));
    netsnmp_set_row_column(row, 3, ASN_INTEGER, (char*)&two, sizeof(two));
    netsnmp_set_row_column(row, 4, ASN_OCTET_STR, stuff, 1);
    
    netsnmp_table_dataset_add_row(table_set, row);
  }
  netsnmp_register_auto_data_table(table_set, NULL);
  
}

int main (int argc, char **argv) {

  netsnmp_enable_subagent();
  snmp_disable_log();
  snmp_enable_stderrlog();

  init_agent("lldpAgent");

  REGISTER(global, messageTxInterval, ASN_INTEGER);
  REGISTER(global, messageTxHoldMultiplier, ASN_INTEGER);
  REGISTER(global, reinitDelay, ASN_INTEGER);
  REGISTER(global, txDelay, ASN_INTEGER);
  REGISTER(global, notificationInterval, ASN_INTEGER);

  REGISTER(stats, lastChangeTime, ASN_TIMETICKS);
  REGISTER(stats, inserts, ASN_GAUGE);
  REGISTER(stats, deletes, ASN_GAUGE);
  REGISTER(stats, drops, ASN_GAUGE);
  REGISTER(stats, ageouts, ASN_GAUGE);
  
  REGISTER(local, chassisIdSubtype, ASN_INTEGER);
  REGISTER_S(local, chassisId, ASN_OCTET_STR);
  REGISTER(local, sysName, ASN_OCTET_STR);
  REGISTER(local, sysDesc, ASN_OCTET_STR);
  REGISTER_FS(local, sysCapSupported, one, ASN_OCTET_STR);
  REGISTER_FS(local, sysCapEnabled, one, ASN_OCTET_STR);

  register_lldpPortConfig();

  populate_r_entries();

  init_snmp("lldpAgent");

  while(1)
    agent_check_and_process(1);

  snmp_shutdown("lldpAgent");
  
  return 0;
}


