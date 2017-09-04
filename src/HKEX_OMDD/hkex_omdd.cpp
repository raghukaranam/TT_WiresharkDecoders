/*
 * hkex_omdd.cpp
 *
 *  Created on: Sep 4, 2017
 *      Author: raghu
 */

#include<iostream>
#include<vector>
#include<map>
#include<list>
#include<string>
#include<tuple>
#include <config.h>
#include <epan/packet.h>
#include "../legacy_defs.h"
#include "../Protocol.h"
using namespace std;

static int ett_hkexomdd = -1, ett_proto_hkexomdd_msg = -1;
static int proto_hkexomdd = -1;

Protocol hkex_proto_list("omdd");

static
#ifdef __WIRESHARK_1_8_10
void dissect_hkexomdd(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
#else
int dissect_hkexomdd(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void *data)
#endif
		{
	//Sets str in Tree.
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "HKEX OMDD");
	//Clears Info
	col_clear(pinfo->cinfo, COL_INFO);

	proto_tree* ti1 = proto_tree_add_item(tree, proto_hkexomdd, tvb, 0, -1, ENC_NA);
	proto_tree* proto_subtree = proto_item_add_subtree(ti1, ett_hkexomdd);
	unsigned int start_index = 0;
	proto_tree_add_item(proto_subtree, hkex_proto_list["PktSize"], tvb, start_index, 2, ENC_LITTLE_ENDIAN);
	start_index += 2;
	proto_tree_add_item(proto_subtree, hkex_proto_list["MsgCount"], tvb, start_index, 1, ENC_LITTLE_ENDIAN);
	start_index += 2;
	proto_tree_add_item(proto_subtree, hkex_proto_list["SeqNum"], tvb, start_index, 4, ENC_LITTLE_ENDIAN);
	start_index += 4;
	guint64 timestamp;
	nstime_t ts_nstime;
	timestamp = tvb_get_letoh64(tvb, start_index);
	ts_nstime.secs = timestamp / 1000000000;
	ts_nstime.nsecs = timestamp % 1000000000;

	proto_tree_add_time(proto_subtree, hkex_proto_list["SendTimestamp"], tvb, start_index, 8, &ts_nstime);
	start_index += 8;
#ifndef __WIRESHARK_1_8_10
	return start_index + 1;
#endif
}
void proto_register_hkexomdd(void) {
	hkex_proto_list.add("SeqNum", FT_UINT32);
	hkex_proto_list.add("SendTimestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL);
	hkex_proto_list.add("MsgSize", FT_UINT16);
	hkex_proto_list.add("PktSize", FT_UINT16);
	hkex_proto_list.add("MsgCount", FT_UINT8);
	hkex_proto_list.add("MsgType", FT_UINT16);

	/** Setup protocol subtree array */
	static gint *ett[] = { &ett_hkexomdd, &ett_proto_hkexomdd_msg };

	/** registering the myproto protocol with 3 names */
	proto_hkexomdd = proto_register_protocol("OMDD", /** PROTONAME */
	"omdd", /**  PROTOSHORTNAME */
	"omdd" /**  PROTOABBREV  */
	);

	//auto hf_myproto = proto_registrar_get_nth(proto_myproto);

	/** Register header fields and sub-trees. */
	hkex_proto_list.prepareFields();
	hkex_proto_list.registerFields(proto_hkexomdd);

	/**  To register subtree types, pass an array of pointers */
	proto_register_subtree_array(ett, array_length(ett));

}
void proto_reg_handoff_hkexomdd(void) {
	/** the handle for the dynamic dissector */
	dissector_handle_t myproto_handle;

	myproto_handle = create_dissector_handle(dissect_hkexomdd, proto_hkexomdd);
	const int registered_ports[] = { 51000, 51001, 51002, 51003, 51004, 51005 };
	for (const auto &port : registered_ports)
		dissector_add_uint("udp.port", port, myproto_handle);
}
