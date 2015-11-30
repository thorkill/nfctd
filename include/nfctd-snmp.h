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

#ifndef NFCTD_H
#define NFCTD_H

/*
 * function declarations
 */
void            init_nfctd(void);
void            initialize_table_nfctTable(void);
struct nfctTable_entry *nfctTable_get_by_groupId(u_long);
struct nfctTable_entry *nfctTable_createEntry(u_long);

Netsnmp_Node_Handler nfctTable_handler;
Netsnmp_First_Data_Point nfctTable_get_first_data_point;
Netsnmp_Next_Data_Point nfctTable_get_next_data_point;

/*
 * column number definitions for table nfctTable
 */
#define COLUMN_GROUPID		1
#define COLUMN_IPV4TCPCOUNT		2
#define COLUMN_IPV4TCPASSURED		3
#define COLUMN_IPV4TCPHALFASSURED		4
#define COLUMN_IPV4TCPUNREPLIED		5
#define COLUMN_IPV4TCPSTATESYNSENT		6
#define COLUMN_IPV4TCPSTATESYNRECV		7
#define COLUMN_IPV4TCPSTATEESTABLISHED		8
#define COLUMN_IPV4TCPSTATEFINWAIT		9
#define COLUMN_IPV4TCPSTATECLOSEWAIT		10
#define COLUMN_IPV4TCPSTATELASTACK		11
#define COLUMN_IPV4TCPSTATETIMEWAIT		12
#define COLUMN_IPV4TCPSTATECLOSE		13
#define COLUMN_IPV4TCPSTATESYNSENTAGAIN		14
#define COLUMN_IPV4UDPCOUNT		15
#define COLUMN_IPV4UDPASSURED		16
#define COLUMN_IPV4UDPHALFASSURED		17
#define COLUMN_IPV4UDPUNREPLIED		18
#define COLUMN_IPV4ICMPCOUNT		19
#define COLUMN_IPV4ICMPASSURED		20
#define COLUMN_IPV4ICMPHALFASSURED		21
#define COLUMN_IPV4ICMPUNREPLIED		22
#define COLUMN_IPV6TCPCOUNT		23
#define COLUMN_IPV6TCPASSURED		24
#define COLUMN_IPV6TCPHALFASSURED		25
#define COLUMN_IPV6TCPUNREPLIED		26
#define COLUMN_IPV6TCPSTATESYNSENT		27
#define COLUMN_IPV6TCPSTATESYNRECV		28
#define COLUMN_IPV6TCPSTATEESTABLISHED		29
#define COLUMN_IPV6TCPSTATEFINWAIT		30
#define COLUMN_IPV6TCPSTATECLOSEWAIT		31
#define COLUMN_IPV6TCPSTATELASTACK		32
#define COLUMN_IPV6TCPSTATETIMEWAIT		33
#define COLUMN_IPV6TCPSTATECLOSE		34
#define COLUMN_IPV6TCPSTATESYNSENTAGAIN		35
#define COLUMN_IPV6UDPCOUNT		36
#define COLUMN_IPV6UDPASSURED		37
#define COLUMN_IPV6UDPHALFASSURED		38
#define COLUMN_IPV6UDPUNREPLIED		39
#define COLUMN_IPV6ICMPCOUNT		40
#define COLUMN_IPV6ICMPASSURED		41
#define COLUMN_IPV6ICMPHALFASSURED		42
#define COLUMN_IPV6ICMPUNREPLIED		43
#define COLUMN_BPFFILTER		44
#define COLUMN_LABEL		45


/*
 * Typical data structure for a row entry
 */
struct nfctTable_entry {
  /*
   * Index values
   */
  u_long          groupId;

  /*
   * Column values
   */
  u_long          ipv4TcpCount;
  u_long          ipv4TcpAssured;
  u_long          ipv4TcpHalfAssured;
  u_long          ipv4TcpUnreplied;
  u_long          ipv4TcpStateSynSent;
  u_long          ipv4TcpStateSynRecv;
  u_long          ipv4TcpStateEstablished;
  u_long          ipv4TcpStateFinWait;
  u_long          ipv4TcpStateCloseWait;
  u_long          ipv4TcpStateLastAck;
  u_long          ipv4TcpStateTimeWait;
  u_long          ipv4TcpStateClose;
  u_long          ipv4TcpStateSynSentAgain;
  u_long          ipv4UdpCount;
  u_long          ipv4UdpAssured;
  u_long          ipv4UdpHalfAssured;
  u_long          ipv4UdpUnreplied;
  u_long          ipv4IcmpCount;
  u_long          ipv4IcmpAssured;
  u_long          ipv4IcmpHalfAssured;
  u_long          ipv4IcmpUnreplied;
  u_long          ipv6TcpCount;
  u_long          ipv6TcpAssured;
  u_long          ipv6TcpHalfAssured;
  u_long          ipv6TcpUnreplied;
  u_long          ipv6TcpStateSynSent;
  u_long          ipv6TcpStateSynRecv;
  u_long          ipv6TcpStateEstablished;
  u_long          ipv6TcpStateFinWait;
  u_long          ipv6TcpStateCloseWait;
  u_long          ipv6TcpStateLastAck;
  u_long          ipv6TcpStateTimeWait;
  u_long          ipv6TcpStateClose;
  u_long          ipv6TcpStateSynSentAgain;
  u_long          ipv6UdpCount;
  u_long          ipv6UdpAssured;
  u_long          ipv6UdpHalfAssured;
  u_long          ipv6UdpUnreplied;
  u_long          ipv6IcmpCount;
  u_long          ipv6IcmpAssured;
  u_long          ipv6IcmpHalfAssured;
  u_long          ipv6IcmpUnreplied;
  char            bpfFilter[255];
  size_t          bpfFilter_len;
  char            label[255];
  size_t          label_len;

  /*
   * Illustrate using a simple linked list
   */
  int             valid;
  struct nfctTable_entry *next;
};


#endif                          /* NFCTD_H */
