/*
 * Protocol.h
 *
 *  Created on: Sep 4, 2017
 *      Author: raghu
 */

#ifndef SRC_PROTOCOL_H_
#define SRC_PROTOCOL_H_

#include<iostream>
#include<vector>
#include<map>
#include<list>
#include<string>
#include<tuple>
#include <config.h>
#include <epan/packet.h>

using namespace std;

struct Type {
	string name, length, primitiveType, semanticType, presence, const_value;
};
struct Group {
	string name, id, blockLength, dimensionType;
};
struct Field {
	string name, id, type, offset, semanticType;
	Group group;
};

struct Message {
	string name, id, blockLength;
	vector<Field> fields;
};

class Protocol {
public:
	vector<hf_register_info> hf_list;
	map<string, int> hf_vals;

	//Data read from xml
	map<string, Type> types;
	map<string, vector<Type> > ctypes;
	map<string, map<string, string> > etypes;
	map<string, tuple<int, ftenum, int> > primitive_type_data;

	list<string> composites;
	map<int, Message> messages;

	string abbr;
	Protocol(const char *name) :
			abbr(name) {
		primitive_type_data["char"]= {1,FT_STRING,BASE_NONE};
		primitive_type_data["int8"] = {1,FT_INT8,BASE_DEC};
		primitive_type_data["uint8"] = {1,FT_UINT8,BASE_DEC};
		primitive_type_data["int16"] = {2,FT_INT16,BASE_DEC};
		primitive_type_data["uint16"] = {2,FT_UINT16,BASE_DEC};
		primitive_type_data["int32"] = {4,FT_INT32,BASE_DEC};
		primitive_type_data["uint32"] = {4,FT_UINT32,BASE_DEC};
		primitive_type_data["int64"] = {8,FT_INT64,BASE_DEC};
		primitive_type_data["uint64"] = {8,FT_UINT64,BASE_DEC};
		primitive_type_data["UTCTimestamp"] = {8,FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL};
	}
	void add(const char *name, ftenum _ft_entype, int display = BASE_DEC) {
		string abbr_name = abbr + "." + name;
		if(hf_vals.find(abbr_name)!=hf_vals.end())
		{
			//printf("Skip to add %s\n",abbr_name.c_str());
			return;
		}
		hf_register_info tmp;
		memset(&tmp, 0, sizeof(tmp));
		HFILL_INIT(tmp);
		hf_vals[abbr_name] = -1;
		auto it = hf_vals.find(abbr_name);
		if (it != hf_vals.end()) {
			tmp.hfinfo.abbrev = it->first.c_str();
		}
		tmp.hfinfo.name = name;
		tmp.hfinfo.type = _ft_entype;
		tmp.hfinfo.display = display;
		//printf("%s = %d\r\n",name,_ft_entype);
		hf_list.push_back(tmp);
	}
	auto registerFields(int protocol) {
		for (auto &a : hf_list)
		a.p_id = &hf_vals[a.hfinfo.abbrev];
		auto count = hf_list.size();
		//printf("Registered: %lu fields\n",count);
		if (count > 0)
		proto_register_field_array(protocol, &hf_list[0], count);
		return count;
	}
	auto operator[](auto v) {
		return hf_vals[abbr + "." + v];
	}
	static bool getFirstAttrValue(rapidxml::xml_node<> *node, string name, string &value) {
		auto a = node->first_attribute(name.c_str());
		if (a) {
			value = a->value();
			return true;
		}
		return false;
	}
	static void fillFields(Field &f, rapidxml::xml_node<> *field) {
		getFirstAttrValue(field, "name", f.name);
		getFirstAttrValue(field, "id", f.id);
		getFirstAttrValue(field, "type", f.type);
		getFirstAttrValue(field, "offset", f.offset);
		getFirstAttrValue(field, "semanticType", f.semanticType);
	}
	static void fillType(Type &data, rapidxml::xml_node<> *type) {
		getFirstAttrValue(type, "name", data.name);
		getFirstAttrValue(type, "length", data.length);
		getFirstAttrValue(type, "primitiveType", data.primitiveType);
		getFirstAttrValue(type, "semanticType", data.semanticType);
		getFirstAttrValue(type, "presence", data.presence);
		if (data.presence == "constant")
		data.const_value = type->value();
	}
	auto getTypeInfo(string type) {
		int length=-1;
		if (types.find(type) != types.end()) {
			string t = types[type].primitiveType;
			//printf("Length of %s = %s %d\n",type.c_str(),types[type].length.c_str(),length);
			if(types[type].length.size()>0)
			{
				length=atoi(types[type].length.c_str());
			}
			if (types.find(t) != types.end())
			type = types[t].primitiveType;
			else
			type = t;
		}
		auto it = primitive_type_data.find(type);
		if (it != primitive_type_data.end())
		{
			auto ret=it->second;
			if(length>0)
			get<0>(ret)=length;
			return ret;
		}
		cerr << "Cannot figure out length for type: " << type << ". Templates xml / Source-code needs cleanup." << endl;
		return make_tuple(length,(ftenum)-1,-1);
	}

	int getLenOfType(string type) {
		return get<0>(getTypeInfo(type));
	}
	void addFieldToProtoTree(proto_tree * tree, tvbuff_t * tvb, unsigned int &index,bool is_composite,bool is_constant,const Field &f)
	{
		int len=0;
		if(is_composite)
		{
			for(const auto &cf : ctypes[f.type])
			{
				if(cf.presence!="constant")
				{ // not constant
					len=getLenOfType(cf.primitiveType);
					//printf("Composite: %s\n",(f.name+"."+cf.name).c_str());
					proto_tree_add_item(tree, (*this)[f.name+"."+cf.name], tvb, index, len, ENC_LITTLE_ENDIAN);
					index+=len;
				}
			}
		}
		else if (!is_constant) {
			len=getLenOfType(f.type);
			//printf("Field: %s Type: %s Size: %d\n", f.name.c_str(), f.type.c_str(), len);
			if(f.semanticType=="UTCTimestamp")
			{
				guint64 timestamp;
				nstime_t ts_nstime;
				timestamp = tvb_get_letoh64(tvb, index);
				ts_nstime.secs = timestamp / 1000000000;
				ts_nstime.nsecs = timestamp % 1000000000;
				proto_tree_add_time(tree, (*this)[f.name], tvb, index, len, &ts_nstime);
			}
			else
			proto_tree_add_item(tree, (*this)[f.name], tvb, index, len, ENC_LITTLE_ENDIAN);
			index+=len;
		}
	}
	void tree_add_template(proto_tree * tree, tvbuff_t * tvb, int template_id, unsigned int &index) {
		Message &msg = messages[template_id];
		//printf("Decoding Template: %d - %s\n", template_id, msg.name.c_str());
		int msg_start_index=index;
		for (size_t i=0;i<msg.fields.size();i++) {
			const auto &f=msg.fields[i];
			if(f.name.size()==0)
			continue;
			bool is_composite = ctypes.find(f.type) != ctypes.end();
			bool is_group = f.group.name.size()>0;
			bool is_constant=false;
			if(types.find(f.type)!=types.end())
			{
				is_constant=types[f.type].const_value.size()>0;
			}
			//Todo add logic for group
			if(is_group)
			{
				string group_type=f.group.dimensionType;
				if(index-msg_start_index < (unsigned)atoi(msg.blockLength.c_str()))
				index += atoi(msg.blockLength.c_str()) -(index-msg_start_index);

				//Get groups type to determine length
				if(group_type=="groupSize" || group_type=="groupSize8Byte")
				{
					if(group_type == "groupSize8Byte")
					index +=5;
					uint16_t block_length=tvb_get_guint16(tvb, index,ENC_LITTLE_ENDIAN);
					index+=2;
					uint8_t num_group=tvb_get_guint8(tvb, index);
					index++;

					//Add fields in loop for groups
					for(int j=0;j<num_group;j++)
					{
						unsigned int index_start=index;
						for(size_t k=i;k<msg.fields.size() && msg.fields[k].group.name==f.group.name;k++)
						{
							const auto &f=msg.fields[k];

							bool is_composite = ctypes.find(f.type) != ctypes.end();
							bool is_constant=false;
							if(types.find(f.type)!=types.end())
							{
								is_constant=types[f.type].const_value.size()>0;
							}
							addFieldToProtoTree(tree, tvb, index_start,is_composite,is_constant,f);
						}
						index += block_length;
					}

					//printf("%s Group in %u/%d\n",f.name.c_str(),block_length,num_group);
					for(;i<msg.fields.size() && msg.fields[i].group.name==f.group.name;i++);
					i--;
				}
				else
				{
					//printf("Unable to handle %s, Possible Bug please report this.",group_type.c_str());
				}
			}
			else
			addFieldToProtoTree(tree, tvb, index,is_composite,is_constant,f);
			//proto_tree_add_item(proto_subtree_m, proto_list["Version"], tvb, 20, 2, ENC_LITTLE_ENDIAN);
		}
	}
	void prepareFields() {
		for (const auto &m : messages) {
			const auto &msg = m.second;
			for (const auto &f : msg.fields)
			{
				/*char *ch=new char[f.name.size()+1];
				 ch[f.name.size()]=0;
				 memcpy(ch,f.name.c_str(),f.name.size());*/
				// Only non-composite types
				if(ctypes.find(f.type) == ctypes.end())
				{
					auto info=getTypeInfo(f.type);
					if(f.semanticType=="UTCTimestamp")
					info=getTypeInfo(f.semanticType);
					//printf("Adding: %s\n",f.name.c_str());
					add(f.name.c_str(), get<1>(info),get<2>(info));
				}
				else
				{ // It composite
					for(const auto &ct:ctypes[f.type])
					{
						auto info=getTypeInfo(ct.primitiveType);
						//printf("Adding: %s\n",(f.name+"."+ct.name).c_str());
						composites.push_back(f.name+"."+ct.name);
						add(composites.rbegin()->c_str(), get<1>(info),get<2>(info));
					}
				}

			}
		}
	}
	void parseTemplatesXML(const char *xml,int _xml_len) {
		char data[_xml_len + 1];
		data[_xml_len] = 0;
		memcpy(data, xml, _xml_len);
		//printf("Template: %s\n",data);
		//map<string,FixTagAttributes> &tags=TAG_DEFINITIONS;
		using namespace rapidxml;
		xml_document<> doc;
		doc.parse<0>(data);
		for (xml_node<> *node = doc.first_node()->first_node(); node; node = node->next_sibling()) {
			xml_node<> *tags = node;

			string Tag = tags->value();
			string Name = tags->name();
			//printf("Name: %s\n", Name.c_str());
			if (Name == "types") {
				for (auto type = node->first_node(); type; type = type->next_sibling()) {
					string tagname = type->name();
					if (tagname == "type") {
						Type data;
						fillType(data, type);
						types[data.name] = data;
					} else if (tagname == "composite") {
						Type t;
						getFirstAttrValue(type, "name", t.name);
						getFirstAttrValue(type, "encodingType", t.primitiveType);
						//types[t.name]=t;
						for (auto composite_type = type->first_node(); composite_type; composite_type = composite_type->next_sibling()) {
							string tagname = composite_type->name();
							if (tagname == "type") {
								Type data;
								fillType(data, composite_type);
								ctypes[t.name].push_back(data);
								/*
								 data.name=t.name +"."+ data.name;
								 types[data.name]=data;
								 //printf("Added Composite: %s\n",data.name.c_str());*/
							}
						}
					} else if (tagname == "enum" || tagname == "set") {
						Type t;
						getFirstAttrValue(type, "name", t.name);
						getFirstAttrValue(type, "encodingType", t.primitiveType);
						types[t.name] = t;

						for (auto composite_type = type->first_node(); composite_type; composite_type = composite_type->next_sibling()) {
							string tagname = composite_type->name();
							if (tagname == "validValue" || tagname == "choice") {
								string e_name, e_value = composite_type->value();
								getFirstAttrValue(composite_type, "name", e_name);
								////printf("%s: %s = %s\n",tagvalue.c_str(),e_name.c_str(),e_value.c_str());
								etypes[t.name][e_name] = e_value;
							}
						}
					}
				}
			} else if (Name == "ns2:message") {
				Message msg;
				getFirstAttrValue(node, "name", msg.name);
				getFirstAttrValue(node, "id", msg.id);
				getFirstAttrValue(node, "blockLength", msg.blockLength);

				for (auto field = node->first_node(); field; field = field->next_sibling()) {

					string tagname = field->name();
					if (tagname == "field") {
						Field f;
						fillFields(f, field);
						//printf("%s Field: %s\n",msg.name.c_str(),f.name.c_str());
						msg.fields.push_back(f);
					} else if (tagname == "group") {
						Group g;
						getFirstAttrValue(field, "name", g.name);
						getFirstAttrValue(field, "blockLength", g.blockLength);
						getFirstAttrValue(field, "dimensionType", g.dimensionType);
						//printf("%s Group: %s\n", msg.name.c_str(), g.name.c_str());

						for (auto subfield = field->first_node(); subfield; subfield = subfield->next_sibling()) {
							Field f;
							fillFields(f, subfield);
							f.group = g;
							msg.fields.push_back(f);
							//printf("%s GroupSubField: %s\n", msg.name.c_str(), f.name.c_str());

						}

					}

				}
				int template_id = atoi(msg.id.c_str());
				messages[template_id] = msg;
			}

		}

	}
}
;

#endif /* SRC_PROTOCOL_H_ */
