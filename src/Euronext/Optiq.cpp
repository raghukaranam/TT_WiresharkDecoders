/*
 * Optiq.cpp
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

static int ett_euronext_optiq = -1, ett_proto_euronext_optiq_msg = -1;
static int proto_euronext_optiq = -1;

Protocol euronext_optiq_proto_list("EURONEXT Optiq");

static
#ifdef __WIRESHARK_1_8_10
void dissect_euronext_optiq(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
#else
int dissect_euronext_optiq(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void *data)
#endif
		{
	//Sets str in Tree.
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "EURONEXT Optiq");
	//Clears Info
	col_clear(pinfo->cinfo, COL_INFO);

	proto_tree* ti1 = proto_tree_add_item(tree, proto_euronext_optiq, tvb, 0, -1, ENC_NA);
	proto_tree* proto_subtree = proto_item_add_subtree(ti1, ett_euronext_optiq);
	unsigned int start_index = 0;

		guint64 timestamp;
		nstime_t ts_nstime;
		timestamp = tvb_get_letoh64(tvb, 0);
		ts_nstime.secs = timestamp / 1000000000;
		ts_nstime.nsecs = timestamp % 1000000000;

		proto_tree_add_time(proto_subtree, euronext_optiq_proto_list["OptiqTimestamp"], tvb, start_index, 8, &ts_nstime);
		start_index += 8;
		proto_tree_add_item(proto_subtree, euronext_optiq_proto_list["PacketSeqNum"], tvb, start_index, 4, ENC_LITTLE_ENDIAN);
		start_index += 4;
		proto_tree_add_item(proto_subtree, euronext_optiq_proto_list["PacketFlagsNum"], tvb, start_index, 2, ENC_LITTLE_ENDIAN);
		start_index += 2;
		proto_tree_add_item(proto_subtree, euronext_optiq_proto_list["ChannelID"], tvb, start_index, 2, ENC_LITTLE_ENDIAN);
		start_index += 2;
#ifndef __WIRESHARK_1_8_10
	return start_index + 1;
#endif
}
void proto_register_euronext_optiq(void) {
	euronext_optiq_proto_list.add("OptiqTimestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL);
	euronext_optiq_proto_list.add("PacketSeqNum", FT_UINT32);
	euronext_optiq_proto_list.add("PacketFlagsNum", FT_UINT16);
	euronext_optiq_proto_list.add("ChannelID", FT_UINT16);


	/** Setup protocol subtree array */
	static gint *ett[] = { &ett_euronext_optiq, &ett_proto_euronext_optiq_msg };

	/** registering the myproto protocol with 3 names */
	proto_euronext_optiq = proto_register_protocol("EURONEXT Optiq", /** PROTONAME */
	"optiq", /**  PROTOSHORTNAME */
	"optiq" /**  PROTOABBREV  */
	);

	//auto hf_myproto = proto_registrar_get_nth(proto_myproto);

	/** Register header fields and sub-trees. */
	euronext_optiq_proto_list.prepareFields();
	euronext_optiq_proto_list.registerFields(proto_euronext_optiq);

	/**  To register subtree types, pass an array of pointers */
	proto_register_subtree_array(ett, array_length(ett));

}
void proto_reg_handoff_euronext_optiq(void) {
	/** the handle for the dynamic dissector */
	dissector_handle_t myproto_handle;

	myproto_handle = create_dissector_handle(dissect_euronext_optiq, proto_euronext_optiq);
	const int registered_ports[] = { 10140,10144,10175,10179,10180,10184,10185,10189,10190,10194,10200,10204,10210,10214,10215,10219,10220,10224,10230,10234,10240,10244,10245,10249,11140,11144,11175,11179,11180,11184,11185,11189,11190,11194,11200,11204,11210,11214,11215,11219,11220,11224,11230,11234,11240,11244,1985,20140,20143,20175,20178,20180,20183,20185,20188,20190,20193,20200,20203,20210,20213,20215,20218,20220,20223,20230,20233,20240,20243,20245,20248,21140,21143,21175,21178,21180,21183,21185,21188,21190,21193,21200,21203,21210,21213,21215,21218,21220,21223,21230,21233,21240,21243 };
	for (const auto &port : registered_ports)
		dissector_add_uint("udp.port", port, myproto_handle);
}
