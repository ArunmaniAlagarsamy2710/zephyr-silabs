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

#define GET_INTERFACE (0x03)
#define ERROR_CODE_CHECK(sdk_error)                                                                \
	((sdk_error) == SL_STATUS_FAIL                    ? -EIO                                   \
	 : (sdk_error) == SL_STATUS_NOT_INITIALIZED       ? -ENODEV                                \
	 : (sdk_error) == SL_STATUS_NOT_SUPPORTED         ? -ENOTSUP                               \
	 : (sdk_error) == SL_STATUS_WIFI_INTERFACE_NOT_UP ? -ENETDOWN                              \
	 : (sdk_error) == SL_STATUS_INVALID_PARAMETER     ? -EINVAL                                \
	 : (sdk_error) == SL_STATUS_INVALID_INDEX         ? -EINVAL                                \
	 : (sdk_error) == SL_STATUS_ALLOCATION_FAILED     ? -ENOMEM                                \
	 : (sdk_error) == SL_STATUS_NOT_AVAILABLE                                                  \
		 ? -EBUSY                                                                          \
		 : -EIO) /* Default mapping to EIO for unknown errors */

struct siwx917_dev {
	struct net_if *iface;
	sl_mac_address_t macaddr;
	sl_wifi_interface_t interface;
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

#endif
