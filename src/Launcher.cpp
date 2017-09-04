/*
 * Launcher.cpp
 *
 *  Created on: Sep 4, 2017
 *      Author: raghu
 */

//#include "CMEMDP30/cmemdp30_decoder.cpp"
#include <config.h>
#include <epan/packet.h>
void proto_register_cmemdp(void);
void proto_reg_handoff_cmemdp(void);

void proto_register_hkexomdd(void);
void proto_reg_handoff_hkexomdd(void);


void proto_register_eurex(void);
void proto_reg_handoff_eurex(void);

void proto_register_euronext_xdp(void);
void proto_reg_handoff_euronext_xdp(void);

void proto_register_euronext_optiq(void);
void proto_reg_handoff_euronext_optiq(void);

extern "C" {
#if defined(_WIN64)
__declspec(dllexport)
#endif
void plugin_register(void) {
	proto_register_cmemdp();
	proto_register_hkexomdd();
	proto_register_eurex();
	proto_register_euronext_xdp();
	proto_register_euronext_optiq();
}
#if defined(_WIN64)
__declspec(dllexport)
#endif
void plugin_reg_handoff(void) {
	proto_reg_handoff_cmemdp();
	proto_reg_handoff_hkexomdd();
	proto_reg_handoff_eurex();
	proto_reg_handoff_euronext_xdp();
	proto_reg_handoff_euronext_optiq();
}
#if defined(_WIN64)
__declspec(dllexport)
#endif
gchar version[30] = "0.1";

}

