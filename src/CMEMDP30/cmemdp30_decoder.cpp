/*
 * main.cpp
 *
 *  Created on: May 2, 2017
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


static int ett_cmemdp30 = -1, ett_proto_cmemdp_msg = -1;
static int proto_cmemdp = -1;


Protocol cme_proto_list("CMEMDP30");

static
#ifdef __WIRESHARK_1_8_10
void dissect_cmemdp(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
#else
int dissect_cmemdp(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void *data)
#endif
		{
	//Sets str in Tree.
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "CME MDP 3.0");
	//Clears Info
	col_clear(pinfo->cinfo, COL_INFO);

	proto_tree* ti1 = proto_tree_add_item(tree, proto_cmemdp, tvb, 0, -1, ENC_NA);
	proto_tree* proto_subtree = proto_item_add_subtree(ti1, ett_cmemdp30);
	unsigned int start_index = 0;
	proto_tree* proto_subtree_m = proto_item_add_subtree(ti1, ett_proto_cmemdp_msg);
	proto_tree_add_item(proto_subtree, cme_proto_list["MsgSeqNum"], tvb, start_index, 4, ENC_LITTLE_ENDIAN);
	start_index += 4;
	guint64 timestamp;
	nstime_t ts_nstime;
	timestamp = tvb_get_letoh64(tvb, 4);
	ts_nstime.secs = timestamp / 1000000000;
	ts_nstime.nsecs = timestamp % 1000000000;

	proto_tree_add_time(proto_subtree, cme_proto_list["CMETimestamp"], tvb, start_index, 8, &ts_nstime);
	start_index += 8;
	while (start_index + 10 < tvb_reported_length(tvb)) {
		int block_length = tvb_get_guint16(tvb, start_index, ENC_LITTLE_ENDIAN);
		//printf("CME Msg length : %d\n",block_length);
		proto_tree_add_item(proto_subtree_m, cme_proto_list["MsgSize"], tvb, start_index, 2, ENC_LITTLE_ENDIAN);
		start_index += 2;
		proto_tree_add_item(proto_subtree_m, cme_proto_list["BlockLength"], tvb, start_index, 2, ENC_LITTLE_ENDIAN);
		start_index += 2;

		int template_id = tvb_get_guint16(tvb, start_index, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(proto_subtree_m, cme_proto_list["TemplateID"], tvb, start_index, 2, ENC_LITTLE_ENDIAN);
		start_index += 2;
		proto_tree_add_item(proto_subtree_m, cme_proto_list["SchemaID"], tvb, start_index, 2, ENC_LITTLE_ENDIAN);
		start_index += 2;
		proto_tree_add_item(proto_subtree_m, cme_proto_list["Version"], tvb, start_index, 2, ENC_LITTLE_ENDIAN);
		start_index += 2;

		//printf("Template decode start : %d\n",start_index);
		unsigned int index = start_index;
		cme_proto_list.tree_add_template(proto_subtree_m, tvb, template_id, index);
		start_index += block_length - 10;
		//printf("Template decode end : %d\n",start_index);
	}
#ifndef __WIRESHARK_1_8_10
	return start_index + 1;
#endif
}
void proto_register_cmemdp(void) {
#ifdef __APPLE__
	int size_templates_xml = (int)___src_CMEMDP30_templates_FixBinary_xml_len;
    char  *templates_xml = (char *)___src_CMEMDP30_templates_FixBinary_xml;
#else
	extern char _binary____src_CMEMDP30_templates_FixBinary_xml_start, _binary____src_CMEMDP30_templates_FixBinary_xml_end;
	int size_templates_xml = (&_binary____src_CMEMDP30_templates_FixBinary_xml_end - &_binary____src_CMEMDP30_templates_FixBinary_xml_start);
	char * templates_xml = &_binary____src_CMEMDP30_templates_FixBinary_xml_start;
#endif

	cme_proto_list.add("MsgSeqNum", FT_UINT32);
	cme_proto_list.add("CMETimestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL);
	cme_proto_list.add("MsgSize", FT_UINT16);
	cme_proto_list.add("BlockLength", FT_UINT16);
	cme_proto_list.add("TemplateID", FT_UINT16);
	cme_proto_list.add("SchemaID", FT_UINT16);
	cme_proto_list.add("Version", FT_UINT16);
	cme_proto_list.parseTemplatesXML(templates_xml, size_templates_xml);

	/** Setup protocol subtree array */
	static gint *ett[] = { &ett_cmemdp30, &ett_proto_cmemdp_msg };

	/** registering the myproto protocol with 3 names */
	proto_cmemdp = proto_register_protocol("CMEMDP30", /** PROTONAME */
	"cmemdp30", /**  PROTOSHORTNAME */
	"cmemdp30" /**  PROTOABBREV  */
	);

	//auto hf_myproto = proto_registrar_get_nth(proto_myproto);

	/** Register header fields and sub-trees. */
	cme_proto_list.prepareFields();
	cme_proto_list.registerFields(proto_cmemdp);

	/**  To register subtree types, pass an array of pointers */
	proto_register_subtree_array(ett, array_length(ett));
}
void proto_reg_handoff_cmemdp(void) {
	/** the handle for the dynamic dissector */
	dissector_handle_t myproto_handle;

	myproto_handle = create_dissector_handle(dissect_cmemdp, proto_cmemdp);
	const int cme_ports[] = { 10000, 14310, 14311, 14312, 14313, 14314, 14315, 14316, 14317, 14318, 14319, 14320, 14321, 14340, 14341, 14342, 14343, 14344, 14345, 14346, 14360, 14361, 14380, 14381,
			14382, 14383, 14384, 14385, 14386, 14387, 14410, 14411, 14430, 14431, 14440, 14441, 14450, 14460, 14461, 14520, 14521, 15310, 15311, 15312, 15313, 15314, 15315, 15316, 15317, 15318, 15319,
			15320, 15321, 15340, 15341, 15342, 15343, 15344, 15345, 15346, 15360, 15361, 15380, 15381, 15382, 15383, 15384, 15385, 15386, 15387, 15410, 15411, 15430, 15431, 15440, 15441, 15450, 15460,
			15461, 15520, 15521, 22310, 22311, 22312, 22313, 22314, 22315, 22316, 22317, 22318, 22319, 22320, 22321, 22340, 22341, 22342, 22343, 22344, 22345, 22346, 22360, 22361, 22380, 22381, 22382,
			22383, 22384, 22385, 22386, 22387, 22410, 22411, 22430, 22431, 22440, 22441, 22450, 22460, 22461, 23310, 23311, 23312, 23313, 23314, 23315, 23316, 23317, 23318, 23319, 23320, 23321, 23340,
			23341, 23342, 23343, 23344, 23345, 23346, 23360, 23361, 23380, 23381, 23382, 23383, 23384, 23385, 23386, 23387, 23410, 23411, 23430, 23431, 23440, 23441, 23450, 23460, 23461 };
	for (const auto &port : cme_ports)
		dissector_add_uint("udp.port", port, myproto_handle);
}
