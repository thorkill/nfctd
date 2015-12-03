/**
 * nfctd - netlinkfilter-conntrack net-snmp statictics
 *
 * Copyright (C) 2015 Rafal Lesniak & Markus Koetter
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include "nfctd-snmp.h"

/** Initializes the nfctd module */
void
init_nfctd(void)
{
    /*
     * here we initialize all the tables we're planning on supporting
     */
    initialize_table_nfctTable();
}

//#Determine the first/last column names

/** Initialize the nfctTable table by defining its contents and how it's structured */
void
initialize_table_nfctTable(void)
{
    static oid       nfctTable_oid[] =
        { 1, 3, 6, 1, 4, 1, 18141, 1, 1, 1, 5, 1 };
    const size_t    nfctTable_oid_len = OID_LENGTH(nfctTable_oid);
    netsnmp_handler_registration *reg;
    netsnmp_iterator_info *iinfo;
    netsnmp_table_registration_info *table_info;

    DEBUGMSGTL(("nfctd:init", "initializing table nfctTable\n"));

    reg =
        netsnmp_create_handler_registration("nfctTable", nfctTable_handler,
                                            nfctTable_oid,
                                            nfctTable_oid_len,
                                            HANDLER_CAN_RONLY);

    table_info = SNMP_MALLOC_TYPEDEF(netsnmp_table_registration_info);
    netsnmp_table_helper_add_indexes(table_info, ASN_UNSIGNED,  /* index: groupId */
                                     0);
    table_info->min_column = COLUMN_GROUPID;
    table_info->max_column = COLUMN_LABEL;

    iinfo = SNMP_MALLOC_TYPEDEF(netsnmp_iterator_info);
    iinfo->get_first_data_point = nfctTable_get_first_data_point;
    iinfo->get_next_data_point = nfctTable_get_next_data_point;
    iinfo->table_reginfo = table_info;

    netsnmp_register_table_iterator(reg, iinfo);

    /*
     * Initialise the contents of the table here
     */
}

struct nfctTable_entry *nfctTable_head;

/*
 * create a new row in the (unsorted) table
 */
struct nfctTable_entry *
nfctTable_createEntry(u_long groupId)
{
    struct nfctTable_entry *entry;

    entry = SNMP_MALLOC_TYPEDEF(struct nfctTable_entry);
    if (!entry)
        return NULL;

    entry->groupId = groupId;
    entry->next = nfctTable_head;
    nfctTable_head = entry;
    return entry;
}

/*
 * find entry by groupId
 */
struct nfctTable_entry *
nfctTable_get_by_groupId(u_long groupid) {
  struct nfctTable_entry *entry, *ret;
  ret = NULL;

  for(entry = nfctTable_head;; entry=entry->next) {
    if (entry->groupId == groupid) {
      ret = entry;
      break;
    }

    if (entry->next == NULL)
      break;
  }
  return ret;
}

/*
 * remove a row from the table
 */
void
nfctTable_removeEntry(struct nfctTable_entry *entry)
{
    struct nfctTable_entry *ptr, *prev;

    if (!entry)
        return;                 /* Nothing to remove */

    for (ptr = nfctTable_head, prev = NULL;
         ptr != NULL; prev = ptr, ptr = ptr->next) {
        if (ptr == entry)
            break;
    }
    if (!ptr)
        return;                 /* Can't find it */

    if (prev == NULL)
        nfctTable_head = ptr->next;
    else
        prev->next = ptr->next;

    SNMP_FREE(entry);           /* XXX - release any other internal resources */
}


/*
 * Example iterator hook routines - using 'get_next' to do most of the work
 */
netsnmp_variable_list *
nfctTable_get_first_data_point(void **my_loop_context,
                               void **my_data_context,
                               netsnmp_variable_list * put_index_data,
                               netsnmp_iterator_info *mydata)
{
    *my_loop_context = nfctTable_head;
    return nfctTable_get_next_data_point(my_loop_context, my_data_context,
                                         put_index_data, mydata);
}

netsnmp_variable_list *
nfctTable_get_next_data_point(void **my_loop_context,
                              void **my_data_context,
                              netsnmp_variable_list * put_index_data,
                              netsnmp_iterator_info *mydata)
{
    struct nfctTable_entry *entry =
        (struct nfctTable_entry *) *my_loop_context;
    netsnmp_variable_list *idx = put_index_data;

    if (entry) {
        snmp_set_var_typed_integer(idx, ASN_UNSIGNED, entry->groupId);
        idx = idx->next_variable;
        *my_data_context = (void *) entry;
        *my_loop_context = (void *) entry->next;
        return put_index_data;
    } else {
        return NULL;
    }
}


/** handles requests for the nfctTable table */
int
nfctTable_handler(netsnmp_mib_handler *handler,
                  netsnmp_handler_registration *reginfo,
                  netsnmp_agent_request_info *reqinfo,
                  netsnmp_request_info *requests)
{

    netsnmp_request_info *request;
    netsnmp_table_request_info *table_info;
    struct nfctTable_entry *table_entry;

    DEBUGMSGTL(("nfctd:handler", "Processing request (%d)\n",
                reqinfo->mode));

    switch (reqinfo->mode) {
        /*
         * Read-support (also covers GetNext requests)
         */
    case MODE_GET:
        for (request = requests; request; request = request->next) {
            table_entry = (struct nfctTable_entry *)
                netsnmp_extract_iterator_context(request);
            table_info = netsnmp_extract_table_info(request);

            switch (table_info->colnum) {
            case COLUMN_GROUPID:
                if (!table_entry) {
                    netsnmp_set_request_error(reqinfo, request,
                                              SNMP_NOSUCHINSTANCE);
                    continue;
                }
                snmp_set_var_typed_integer(request->requestvb,
                                           ASN_UNSIGNED,
                                           table_entry->groupId);
                break;
            case COLUMN_IPV4TCPCOUNT:
                if (!table_entry) {
                    netsnmp_set_request_error(reqinfo, request,
                                              SNMP_NOSUCHINSTANCE);
                    continue;
                }
                snmp_set_var_typed_integer(request->requestvb,
                                           ASN_UNSIGNED,
                                           table_entry->ipv4TcpCount);
                break;
            case COLUMN_IPV4TCPASSURED:
                if (!table_entry) {
                    netsnmp_set_request_error(reqinfo, request,
                                              SNMP_NOSUCHINSTANCE);
                    continue;
                }
                snmp_set_var_typed_integer(request->requestvb,
                                           ASN_UNSIGNED,
                                           table_entry->ipv4TcpAssured);
                break;
            case COLUMN_IPV4TCPHALFASSURED:
                if (!table_entry) {
                    netsnmp_set_request_error(reqinfo, request,
                                              SNMP_NOSUCHINSTANCE);
                    continue;
                }
                snmp_set_var_typed_integer(request->requestvb,
                                           ASN_UNSIGNED,
                                           table_entry->
                                           ipv4TcpHalfAssured);
                break;
            case COLUMN_IPV4TCPUNREPLIED:
                if (!table_entry) {
                    netsnmp_set_request_error(reqinfo, request,
                                              SNMP_NOSUCHINSTANCE);
                    continue;
                }
                snmp_set_var_typed_integer(request->requestvb,
                                           ASN_UNSIGNED,
                                           table_entry->ipv4TcpUnreplied);
                break;
            case COLUMN_IPV4TCPSTATESYNSENT:
                if (!table_entry) {
                    netsnmp_set_request_error(reqinfo, request,
                                              SNMP_NOSUCHINSTANCE);
                    continue;
                }
                snmp_set_var_typed_integer(request->requestvb,
                                           ASN_UNSIGNED,
                                           table_entry->
                                           ipv4TcpStateSynSent);
                break;
            case COLUMN_IPV4TCPSTATESYNRECV:
                if (!table_entry) {
                    netsnmp_set_request_error(reqinfo, request,
                                              SNMP_NOSUCHINSTANCE);
                    continue;
                }
                snmp_set_var_typed_integer(request->requestvb,
                                           ASN_UNSIGNED,
                                           table_entry->
                                           ipv4TcpStateSynRecv);
                break;
            case COLUMN_IPV4TCPSTATEESTABLISHED:
                if (!table_entry) {
                    netsnmp_set_request_error(reqinfo, request,
                                              SNMP_NOSUCHINSTANCE);
                    continue;
                }
                snmp_set_var_typed_integer(request->requestvb,
                                           ASN_UNSIGNED,
                                           table_entry->
                                           ipv4TcpStateEstablished);
                break;
            case COLUMN_IPV4TCPSTATEFINWAIT:
                if (!table_entry) {
                    netsnmp_set_request_error(reqinfo, request,
                                              SNMP_NOSUCHINSTANCE);
                    continue;
                }
                snmp_set_var_typed_integer(request->requestvb,
                                           ASN_UNSIGNED,
                                           table_entry->
                                           ipv4TcpStateFinWait);
                break;
            case COLUMN_IPV4TCPSTATECLOSEWAIT:
                if (!table_entry) {
                    netsnmp_set_request_error(reqinfo, request,
                                              SNMP_NOSUCHINSTANCE);
                    continue;
                }
                snmp_set_var_typed_integer(request->requestvb,
                                           ASN_UNSIGNED,
                                           table_entry->
                                           ipv4TcpStateCloseWait);
                break;
            case COLUMN_IPV4TCPSTATELASTACK:
                if (!table_entry) {
                    netsnmp_set_request_error(reqinfo, request,
                                              SNMP_NOSUCHINSTANCE);
                    continue;
                }
                snmp_set_var_typed_integer(request->requestvb,
                                           ASN_UNSIGNED,
                                           table_entry->
                                           ipv4TcpStateLastAck);
                break;
            case COLUMN_IPV4TCPSTATETIMEWAIT:
                if (!table_entry) {
                    netsnmp_set_request_error(reqinfo, request,
                                              SNMP_NOSUCHINSTANCE);
                    continue;
                }
                snmp_set_var_typed_integer(request->requestvb,
                                           ASN_UNSIGNED,
                                           table_entry->
                                           ipv4TcpStateTimeWait);
                break;
            case COLUMN_IPV4TCPSTATECLOSE:
                if (!table_entry) {
                    netsnmp_set_request_error(reqinfo, request,
                                              SNMP_NOSUCHINSTANCE);
                    continue;
                }
                snmp_set_var_typed_integer(request->requestvb,
                                           ASN_UNSIGNED,
                                           table_entry->ipv4TcpStateClose);
                break;
            case COLUMN_IPV4TCPSTATESYNSENTAGAIN:
                if (!table_entry) {
                    netsnmp_set_request_error(reqinfo, request,
                                              SNMP_NOSUCHINSTANCE);
                    continue;
                }
                snmp_set_var_typed_integer(request->requestvb,
                                           ASN_UNSIGNED,
                                           table_entry->
                                           ipv4TcpStateSynSentAgain);
                break;
            case COLUMN_IPV4UDPCOUNT:
                if (!table_entry) {
                    netsnmp_set_request_error(reqinfo, request,
                                              SNMP_NOSUCHINSTANCE);
                    continue;
                }
                snmp_set_var_typed_integer(request->requestvb,
                                           ASN_UNSIGNED,
                                           table_entry->ipv4UdpCount);
                break;
            case COLUMN_IPV4UDPASSURED:
                if (!table_entry) {
                    netsnmp_set_request_error(reqinfo, request,
                                              SNMP_NOSUCHINSTANCE);
                    continue;
                }
                snmp_set_var_typed_integer(request->requestvb,
                                           ASN_UNSIGNED,
                                           table_entry->ipv4UdpAssured);
                break;
            case COLUMN_IPV4UDPHALFASSURED:
                if (!table_entry) {
                    netsnmp_set_request_error(reqinfo, request,
                                              SNMP_NOSUCHINSTANCE);
                    continue;
                }
                snmp_set_var_typed_integer(request->requestvb,
                                           ASN_UNSIGNED,
                                           table_entry->
                                           ipv4UdpHalfAssured);
                break;
            case COLUMN_IPV4UDPUNREPLIED:
                if (!table_entry) {
                    netsnmp_set_request_error(reqinfo, request,
                                              SNMP_NOSUCHINSTANCE);
                    continue;
                }
                snmp_set_var_typed_integer(request->requestvb,
                                           ASN_UNSIGNED,
                                           table_entry->ipv4UdpUnreplied);
                break;
            case COLUMN_IPV4ICMPCOUNT:
                if (!table_entry) {
                    netsnmp_set_request_error(reqinfo, request,
                                              SNMP_NOSUCHINSTANCE);
                    continue;
                }
                snmp_set_var_typed_integer(request->requestvb,
                                           ASN_UNSIGNED,
                                           table_entry->ipv4IcmpCount);
                break;
            case COLUMN_IPV4ICMPASSURED:
                if (!table_entry) {
                    netsnmp_set_request_error(reqinfo, request,
                                              SNMP_NOSUCHINSTANCE);
                    continue;
                }
                snmp_set_var_typed_integer(request->requestvb,
                                           ASN_UNSIGNED,
                                           table_entry->ipv4IcmpAssured);
                break;
            case COLUMN_IPV4ICMPHALFASSURED:
                if (!table_entry) {
                    netsnmp_set_request_error(reqinfo, request,
                                              SNMP_NOSUCHINSTANCE);
                    continue;
                }
                snmp_set_var_typed_integer(request->requestvb,
                                           ASN_UNSIGNED,
                                           table_entry->
                                           ipv4IcmpHalfAssured);
                break;
            case COLUMN_IPV4ICMPUNREPLIED:
                if (!table_entry) {
                    netsnmp_set_request_error(reqinfo, request,
                                              SNMP_NOSUCHINSTANCE);
                    continue;
                }
                snmp_set_var_typed_integer(request->requestvb,
                                           ASN_UNSIGNED,
                                           table_entry->ipv4IcmpUnreplied);
                break;
            case COLUMN_IPV6TCPCOUNT:
                if (!table_entry) {
                    netsnmp_set_request_error(reqinfo, request,
                                              SNMP_NOSUCHINSTANCE);
                    continue;
                }
                snmp_set_var_typed_integer(request->requestvb,
                                           ASN_UNSIGNED,
                                           table_entry->ipv6TcpCount);
                break;
            case COLUMN_IPV6TCPASSURED:
                if (!table_entry) {
                    netsnmp_set_request_error(reqinfo, request,
                                              SNMP_NOSUCHINSTANCE);
                    continue;
                }
                snmp_set_var_typed_integer(request->requestvb,
                                           ASN_UNSIGNED,
                                           table_entry->ipv6TcpAssured);
                break;
            case COLUMN_IPV6TCPHALFASSURED:
                if (!table_entry) {
                    netsnmp_set_request_error(reqinfo, request,
                                              SNMP_NOSUCHINSTANCE);
                    continue;
                }
                snmp_set_var_typed_integer(request->requestvb,
                                           ASN_UNSIGNED,
                                           table_entry->
                                           ipv6TcpHalfAssured);
                break;
            case COLUMN_IPV6TCPUNREPLIED:
                if (!table_entry) {
                    netsnmp_set_request_error(reqinfo, request,
                                              SNMP_NOSUCHINSTANCE);
                    continue;
                }
                snmp_set_var_typed_integer(request->requestvb,
                                           ASN_UNSIGNED,
                                           table_entry->ipv6TcpUnreplied);
                break;
            case COLUMN_IPV6TCPSTATESYNSENT:
                if (!table_entry) {
                    netsnmp_set_request_error(reqinfo, request,
                                              SNMP_NOSUCHINSTANCE);
                    continue;
                }
                snmp_set_var_typed_integer(request->requestvb,
                                           ASN_UNSIGNED,
                                           table_entry->
                                           ipv6TcpStateSynSent);
                break;
            case COLUMN_IPV6TCPSTATESYNRECV:
                if (!table_entry) {
                    netsnmp_set_request_error(reqinfo, request,
                                              SNMP_NOSUCHINSTANCE);
                    continue;
                }
                snmp_set_var_typed_integer(request->requestvb,
                                           ASN_UNSIGNED,
                                           table_entry->
                                           ipv6TcpStateSynRecv);
                break;
            case COLUMN_IPV6TCPSTATEESTABLISHED:
                if (!table_entry) {
                    netsnmp_set_request_error(reqinfo, request,
                                              SNMP_NOSUCHINSTANCE);
                    continue;
                }
                snmp_set_var_typed_integer(request->requestvb,
                                           ASN_UNSIGNED,
                                           table_entry->
                                           ipv6TcpStateEstablished);
                break;
            case COLUMN_IPV6TCPSTATEFINWAIT:
                if (!table_entry) {
                    netsnmp_set_request_error(reqinfo, request,
                                              SNMP_NOSUCHINSTANCE);
                    continue;
                }
                snmp_set_var_typed_integer(request->requestvb,
                                           ASN_UNSIGNED,
                                           table_entry->
                                           ipv6TcpStateFinWait);
                break;
            case COLUMN_IPV6TCPSTATECLOSEWAIT:
                if (!table_entry) {
                    netsnmp_set_request_error(reqinfo, request,
                                              SNMP_NOSUCHINSTANCE);
                    continue;
                }
                snmp_set_var_typed_integer(request->requestvb,
                                           ASN_UNSIGNED,
                                           table_entry->
                                           ipv6TcpStateCloseWait);
                break;
            case COLUMN_IPV6TCPSTATELASTACK:
                if (!table_entry) {
                    netsnmp_set_request_error(reqinfo, request,
                                              SNMP_NOSUCHINSTANCE);
                    continue;
                }
                snmp_set_var_typed_integer(request->requestvb,
                                           ASN_UNSIGNED,
                                           table_entry->
                                           ipv6TcpStateLastAck);
                break;
            case COLUMN_IPV6TCPSTATETIMEWAIT:
                if (!table_entry) {
                    netsnmp_set_request_error(reqinfo, request,
                                              SNMP_NOSUCHINSTANCE);
                    continue;
                }
                snmp_set_var_typed_integer(request->requestvb,
                                           ASN_UNSIGNED,
                                           table_entry->
                                           ipv6TcpStateTimeWait);
                break;
            case COLUMN_IPV6TCPSTATECLOSE:
                if (!table_entry) {
                    netsnmp_set_request_error(reqinfo, request,
                                              SNMP_NOSUCHINSTANCE);
                    continue;
                }
                snmp_set_var_typed_integer(request->requestvb,
                                           ASN_UNSIGNED,
                                           table_entry->ipv6TcpStateClose);
                break;
            case COLUMN_IPV6TCPSTATESYNSENTAGAIN:
                if (!table_entry) {
                    netsnmp_set_request_error(reqinfo, request,
                                              SNMP_NOSUCHINSTANCE);
                    continue;
                }
                snmp_set_var_typed_integer(request->requestvb,
                                           ASN_UNSIGNED,
                                           table_entry->
                                           ipv6TcpStateSynSentAgain);
                break;
            case COLUMN_IPV6UDPCOUNT:
                if (!table_entry) {
                    netsnmp_set_request_error(reqinfo, request,
                                              SNMP_NOSUCHINSTANCE);
                    continue;
                }
                snmp_set_var_typed_integer(request->requestvb,
                                           ASN_UNSIGNED,
                                           table_entry->ipv6UdpCount);
                break;
            case COLUMN_IPV6UDPASSURED:
                if (!table_entry) {
                    netsnmp_set_request_error(reqinfo, request,
                                              SNMP_NOSUCHINSTANCE);
                    continue;
                }
                snmp_set_var_typed_integer(request->requestvb,
                                           ASN_UNSIGNED,
                                           table_entry->ipv6UdpAssured);
                break;
            case COLUMN_IPV6UDPHALFASSURED:
                if (!table_entry) {
                    netsnmp_set_request_error(reqinfo, request,
                                              SNMP_NOSUCHINSTANCE);
                    continue;
                }
                snmp_set_var_typed_integer(request->requestvb,
                                           ASN_UNSIGNED,
                                           table_entry->
                                           ipv6UdpHalfAssured);
                break;
            case COLUMN_IPV6UDPUNREPLIED:
                if (!table_entry) {
                    netsnmp_set_request_error(reqinfo, request,
                                              SNMP_NOSUCHINSTANCE);
                    continue;
                }
                snmp_set_var_typed_integer(request->requestvb,
                                           ASN_UNSIGNED,
                                           table_entry->ipv6UdpUnreplied);
                break;
            case COLUMN_IPV6ICMPCOUNT:
                if (!table_entry) {
                    netsnmp_set_request_error(reqinfo, request,
                                              SNMP_NOSUCHINSTANCE);
                    continue;
                }
                snmp_set_var_typed_integer(request->requestvb,
                                           ASN_UNSIGNED,
                                           table_entry->ipv6IcmpCount);
                break;
            case COLUMN_IPV6ICMPASSURED:
                if (!table_entry) {
                    netsnmp_set_request_error(reqinfo, request,
                                              SNMP_NOSUCHINSTANCE);
                    continue;
                }
                snmp_set_var_typed_integer(request->requestvb,
                                           ASN_UNSIGNED,
                                           table_entry->ipv6IcmpAssured);
                break;
            case COLUMN_IPV6ICMPHALFASSURED:
                if (!table_entry) {
                    netsnmp_set_request_error(reqinfo, request,
                                              SNMP_NOSUCHINSTANCE);
                    continue;
                }
                snmp_set_var_typed_integer(request->requestvb,
                                           ASN_UNSIGNED,
                                           table_entry->
                                           ipv6IcmpHalfAssured);
                break;
            case COLUMN_IPV6ICMPUNREPLIED:
                if (!table_entry) {
                    netsnmp_set_request_error(reqinfo, request,
                                              SNMP_NOSUCHINSTANCE);
                    continue;
                }
                snmp_set_var_typed_integer(request->requestvb,
                                           ASN_UNSIGNED,
                                           table_entry->ipv6IcmpUnreplied);
                break;
            case COLUMN_BPFFILTER:
                if (!table_entry) {
                    netsnmp_set_request_error(reqinfo, request,
                                              SNMP_NOSUCHINSTANCE);
                    continue;
                }
                snmp_set_var_typed_value(request->requestvb, ASN_OCTET_STR,
                                         (u_char *)table_entry->bpfFilter,
                                         (ssize_t)table_entry->bpfFilter_len);
                break;
            case COLUMN_LABEL:
                if (!table_entry) {
                    netsnmp_set_request_error(reqinfo, request,
                                              SNMP_NOSUCHINSTANCE);
                    continue;
                }
                snmp_set_var_typed_value(request->requestvb, ASN_OCTET_STR,
                                         (u_char *)table_entry->label,
                                         (ssize_t)table_entry->label_len);
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
