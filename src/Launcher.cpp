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

extern "C" {
#if defined(_WIN64)
__declspec(dllexport)
#endif
void plugin_register(void) {
	proto_register_cmemdp();
}
#if defined(_WIN64)
__declspec(dllexport)
#endif
void plugin_reg_handoff(void) {
	proto_reg_handoff_cmemdp();
}
#if defined(_WIN64)
__declspec(dllexport)
#endif
gchar version[30] = "0.1";

}

