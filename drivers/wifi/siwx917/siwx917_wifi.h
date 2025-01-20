/*
 * Copyright (c) 2024 Silicon Laboratories Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SIWX917_WIFI_H
#define SIWX917_WIFI_H

#include <zephyr/net/net_context.h>
#include <zephyr/net/wifi_mgmt.h>
#include <zephyr/net/wifi.h>
#include <zephyr/kernel.h>

#include "sl_ieee802_types.h"
#include "sl_si91x_socket_types.h"
#include "sl_si91x_protocol_types.h"

struct siwx917_dev {
	struct net_if *iface;
	sl_mac_address_t macaddr;
	enum wifi_iface_state state;
	scan_result_cb_t scan_res_cb;

#ifdef CONFIG_WIFI_SIWX917_NET_STACK_OFFLOAD
	struct k_event fds_recv_event;
	sl_si91x_fd_set fds_watch;
	struct {
		net_context_recv_cb_t cb;
		void *user_data;
		struct net_context *context;
	} fds_cb[NUMBER_OF_BSD_SOCKETS];
#endif
};

enum wifi_link_mode get_sl_wifi_protocol_name(sl_wifi_rate_protocol_t rate_protocol)
{
	switch (rate_protocol) {
	case SL_WIFI_RATE_PROTOCOL_B_ONLY:
		return WIFI_1;
	case SL_WIFI_RATE_PROTOCOL_G_ONLY:
		return WIFI_3;
	case SL_WIFI_RATE_PROTOCOL_N_ONLY:
		return WIFI_4;
	case SL_WIFI_RATE_PROTOCOL_AC_ONLY:
		return WIFI_5;
	case SL_WIFI_RATE_PROTOCOL_AX_ONLY:
		return WIFI_6;
	default:
		return WIFI_LINK_MODE_UNKNOWN;
	}
}

int get_sl_wifi_rate_kbps(sl_wifi_rate_t mask)
{
    switch (mask) {
	case SL_WIFI_AUTO_RATE:
	/* AUTO rate doesn't have a specific value */
		return 0;
	case SL_WIFI_RATE_11B_1:
		return 1000;
	case SL_WIFI_RATE_11B_2:
		return 2000;
	case SL_WIFI_RATE_11B_5_5:
		return 5500;
	case SL_WIFI_RATE_11B_11:
		return 11000;
	case SL_WIFI_RATE_11G_6:
		return 6000;
        case SL_WIFI_RATE_11G_9:
		return 9000;
	case SL_WIFI_RATE_11G_12:
		return 12000;
	case SL_WIFI_RATE_11G_18:
		return 18000;
	case SL_WIFI_RATE_11G_24:
		return 24000;
	case SL_WIFI_RATE_11G_36:
		return 36000;
	case SL_WIFI_RATE_11G_48:
		return 48000;
	case SL_WIFI_RATE_11G_54:
		return 54000;
	case SL_WIFI_RATE_11N_MCS0:
		return 72000;
	case SL_WIFI_RATE_11N_MCS1:
		return 14400;
	case SL_WIFI_RATE_11N_MCS2:
		return 21700;
	case SL_WIFI_RATE_11N_MCS3:
		return 28900;
	case SL_WIFI_RATE_11N_MCS4:
		return 43300;
	case SL_WIFI_RATE_11N_MCS5:
		return 57800;
	case SL_WIFI_RATE_11N_MCS6:
		return 65000;
	case SL_WIFI_RATE_11N_MCS7:
		return 72200;
	case SL_WIFI_RATE_11AX_MCS0:
		return 86000;
	case SL_WIFI_RATE_11AX_MCS1:
		return 17200;
	case SL_WIFI_RATE_11AX_MCS2:
		return 25800;
	case SL_WIFI_RATE_11AX_MCS3:
		return 34400;
	case SL_WIFI_RATE_11AX_MCS4:
		return 51600;
	case SL_WIFI_RATE_11AX_MCS5:
		return 68800;
	case SL_WIFI_RATE_11AX_MCS6:
		return 77400;
	case SL_WIFI_RATE_11AX_MCS7:
		return 86000;
	default:
		/* unknown rate */
		return -1;
	}
}

#endif
