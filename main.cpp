/*
 * main.cpp
 *
 *  Created on: May 2, 2017
 *      Author: raghu
 */
#include<iostream>
#include<vector>
#include<map>
#include<string>
using namespace std;
#include <config.h>
#include <epan/packet.h>
#include<rapidxml.h>
void proto_register_cmemdp(void);
void proto_reg_handoff_cmemdp(void);

extern "C" {
void plugin_register(void) {
	proto_register_cmemdp();
}

void plugin_reg_handoff(void) {
	proto_reg_handoff_cmemdp();
}
}

#define MYPROTO_PORT  14341    /*for udp port */
WS_DLL_PUBLIC_DEF gchar version[30] = "0.1";

static int hf_cmemdp30_seqnum = -1, hf_cmemdp30_ts = -1, hf_cmemdp30_MsgSize = -1;
static int ett_cmemdp30 = -1, ett_proto_cmemdp_msg = -1;
static int proto_cmemdp = -1;

class Protocol {
public:
	vector<hf_register_info> hf_list;
	map<string, int> hf_vals;
	string abbr;
	Protocol(const char *name) :
			abbr(name) {

	}
	void add(const char *name, ftenum _ft_entype, int display = BASE_DEC) {
		hf_register_info tmp;
		memset(&tmp, 0, sizeof(tmp));
		HFILL_INIT(tmp);
		string abbr_name = abbr + "." + name;
		hf_vals[abbr_name] = -1;
		auto it = hf_vals.find(abbr_name);
		if (it != hf_vals.end()) {
			tmp.hfinfo.abbrev = it->first.c_str();
		}
		tmp.hfinfo.name = name;
		tmp.hfinfo.type = _ft_entype;
		tmp.hfinfo.display = display;
		hf_list.push_back(tmp);
	}
	auto registerFields(int protocol) {
		for (auto &a : hf_list)
			a.p_id = &hf_vals[a.hfinfo.abbrev];
		auto count = hf_list.size();
		if (count > 0)
			proto_register_field_array(protocol, &hf_list[0], count);
		return count;
	}
	auto operator[](auto v) {
		return hf_vals[abbr + "." + v];
	}
	void parseXML(const char *xml) {
		int _xml_len = strlen(xml);
		char data[_xml_len + 1];
		data[_xml_len] = 0;
		memcpy(data, xml, _xml_len);

		//map<string,FixTagAttributes> &tags=TAG_DEFINITIONS;
		using namespace rapidxml;
		xml_document<> doc;
		doc.parse<0>(data);
		for (xml_node<> *node = doc.first_node()->first_node(); node; node = node->next_sibling()) {
			xml_node<> *tags = node;

			string Tag = tags->value();
			string Name = tags->name();
			xml_attribute<> *attr = tags->first_attribute();
			if(!attr)
				continue;
			string Value = attr->value();



			printf("%s [%s] =%s\n", Tag.c_str(), Name.c_str(), Value.c_str());
		}

	}
};

Protocol list("CMEMDP30");

static int dissect_cmemdp(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void *data) {
	//Sets str in Tree.
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "CME MDP 3.0");
	//Clears Info
	col_clear(pinfo->cinfo, COL_INFO);

	proto_tree* ti1 = proto_tree_add_item(tree, proto_cmemdp, tvb, 0, -1, ENC_NA);
	proto_tree* proto_subtree = proto_item_add_subtree(ti1, ett_cmemdp30);
	proto_tree* proto_subtree_m = proto_item_add_subtree(ti1, ett_proto_cmemdp_msg);

	auto proto_seq = proto_tree_add_item(proto_subtree, list["MsgSeqNum"], tvb, 0, 4, ENC_LITTLE_ENDIAN);
	guint64 timestamp;
	nstime_t ts_nstime;
	timestamp = tvb_get_letoh64(tvb, 4);
	ts_nstime.secs = timestamp / 1000000000;
	ts_nstime.nsecs = timestamp % 1000000000;

	proto_tree_add_time(proto_subtree, list["Timestamp"], tvb, 4, 8, &ts_nstime);
	proto_tree_add_item(proto_subtree_m, list["MsgSize"], tvb, 12, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(proto_subtree_m, list["BlockLength"], tvb, 14, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(proto_subtree_m, list["TemplateID"], tvb, 16, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(proto_subtree_m, list["SchemaID"], tvb, 18, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(proto_subtree_m, list["Version"], tvb, 20, 2, ENC_LITTLE_ENDIAN);

	return tvb_captured_length(tvb);
}
guint8 dissect_inner_pdu(proto_tree *, tvbuff_t *, guint, guint8, packet_info *, proto_item *) {
	cout << __FUNCTION__ << endl;
	return 0;
}

void proto_register_cmemdp(void) {
	extern char _binary____CMEMDP30_templates_FixBinary_xml_start;
	const char * templates_xml = &_binary____CMEMDP30_templates_FixBinary_xml_start;
	list.parseXML(templates_xml);
	cout << __FUNCTION__ << endl;

	/** Field Registration */
	static hf_register_info hf[] = { { &hf_cmemdp30_seqnum, { "MsgSeqNum", "CMEMDP30.MsgSeqNum", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } }, { &hf_cmemdp30_ts, { "Timestamp",
			"CMEMDP30.Timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL } } }, hf1[] = { { &hf_cmemdp30_MsgSize, { "MsgSize", "CMEMDP30.MsgSize", FT_UINT32, BASE_DEC, NULL,
			0x0, NULL, HFILL } } };

	list.add("MsgSeqNum", FT_UINT32);
	list.add("Timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL);
	list.add("MsgSize", FT_UINT16);
	list.add("BlockLength", FT_UINT16);
	list.add("TemplateID", FT_UINT16);
	list.add("SchemaID", FT_UINT16);
	list.add("Version", FT_UINT16);

	/** Setup protocol subtree array */
	static gint *ett[] = { &ett_cmemdp30, &ett_proto_cmemdp_msg };

	/** registering the myproto protocol with 3 names */
	proto_cmemdp = proto_register_protocol("CMEMDP30", /** PROTONAME */
	"cmemdp30", /**  PROTOSHORTNAME */
	"cmemdp30" /**  PROTOABBREV  */
	);

	//auto hf_myproto = proto_registrar_get_nth(proto_myproto);

	/** Register header fields and sub-trees. */
	list.registerFields(proto_cmemdp);

	/**  To register subtree types, pass an array of pointers */
	proto_register_subtree_array(ett, array_length(ett));
	cout << "Register subtree array\n";
}
void proto_reg_handoff_cmemdp(void) {
	/** the handle for the dynamic dissector */
	dissector_handle_t myproto_handle;

	myproto_handle = create_dissector_handle(dissect_cmemdp, proto_cmemdp);
	dissector_add_uint("udp.port", MYPROTO_PORT, myproto_handle);
	dissector_add_uint("udp.port", 15341, myproto_handle);
}
