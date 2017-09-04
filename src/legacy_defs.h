/*
 * legacy_defs.h
 *
 *  Created on: Sep 4, 2017
 *      Author: raghu
 */

#ifndef SRC_LEGACY_DEFS_H_
#define SRC_LEGACY_DEFS_H_


#ifdef __WIRESHARK_1_8_10
#define tvb_get_guint16(a,b,c) tvb_get_letohs(a,b)
#define HFILL_INIT(hf)   \
	hf.hfinfo.id			= -1;   \
	hf.hfinfo.parent		= 0;   \
	hf.hfinfo.ref_type		= HF_REF_TYPE_NONE;   \
	hf.hfinfo.same_name_next	= NULL;
#endif



#endif /* SRC_LEGACY_DEFS_H_ */
