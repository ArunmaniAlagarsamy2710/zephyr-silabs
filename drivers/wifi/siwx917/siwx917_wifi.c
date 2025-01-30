/*
 * Copyright (c) 2023 Antmicro
 * Copyright (c) 2024 Silicon Laboratories Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
#define DT_DRV_COMPAT silabs_siwx917_wifi

#include <zephyr/logging/log.h>
#include <zephyr/sys/__assert.h>

#include "siwx917_wifi.h"
#include "siwx917_wifi_socket.h"

#include "sl_rsi_utility.h"
#include "sl_net_constants.h"
#include "sl_wifi_types.h"
#include "sl_wifi_callback_framework.h"
#include "sl_wifi.h"
#include "sl_net.h"
#include "sl_net_default_values.h"

LOG_MODULE_REGISTER(siwx917_wifi);

NET_BUF_POOL_FIXED_DEFINE(siwx917_tx_pool, 1, _NET_ETH_MAX_FRAME_SIZE, 0, NULL);

int get_sl_wifi_rate_mbps(sl_wifi_rate_t mask)
{
	switch (mask) {
	case SL_WIFI_AUTO_RATE:
		/* AUTO rate doesn't have a specific value */
		return 0;
	case SL_WIFI_RATE_11B_1:
		return 1;
	case SL_WIFI_RATE_11B_2:
		return 2;
	case SL_WIFI_RATE_11B_5_5:
		return 5;
	case SL_WIFI_RATE_11B_11:
		return 11;
	case SL_WIFI_RATE_11G_6:
		return 6;
	case SL_WIFI_RATE_11G_9:
		return 9;
	case SL_WIFI_RATE_11G_12:
		return 12;
	case SL_WIFI_RATE_11G_18:
		return 18;
	case SL_WIFI_RATE_11G_24:
		return 24;
	case SL_WIFI_RATE_11G_36:
		return 36;
	case SL_WIFI_RATE_11G_48:
		return 48;
	case SL_WIFI_RATE_11G_54:
		return 54;
	case SL_WIFI_RATE_11N_MCS0:
		return 7;
	case SL_WIFI_RATE_11N_MCS1:
		return 14;
	case SL_WIFI_RATE_11N_MCS2:
		return 21;
	case SL_WIFI_RATE_11N_MCS3:
		return 28;
	case SL_WIFI_RATE_11N_MCS4:
		return 43;
	case SL_WIFI_RATE_11N_MCS5:
		return 57;
	case SL_WIFI_RATE_11N_MCS6:
		return 65;
	case SL_WIFI_RATE_11N_MCS7:
		return 72;
	case SL_WIFI_RATE_11AX_MCS0:
		return 8;
	case SL_WIFI_RATE_11AX_MCS1:
		return 17;
	case SL_WIFI_RATE_11AX_MCS2:
		return 25;
	case SL_WIFI_RATE_11AX_MCS3:
		return 34;
	case SL_WIFI_RATE_11AX_MCS4:
		return 51;
	case SL_WIFI_RATE_11AX_MCS5:
		return 68;
	case SL_WIFI_RATE_11AX_MCS6:
		return 77;
	case SL_WIFI_RATE_11AX_MCS7:
		return 86;
	default:
		/* unknown rate */
		return -1;
	}
}

static unsigned int siwx917_on_join(sl_wifi_event_t event,
				    char *result, uint32_t result_size, void *arg)
{
	struct siwx917_dev *sidev = arg;

	if (*result != 'C') {
		/* TODO: report the real reason of failure */
		wifi_mgmt_raise_connect_result_event(sidev->iface, WIFI_STATUS_CONN_FAIL);
		sidev->state = WIFI_STATE_INACTIVE;
		return SL_STATUS_OK;
	}

	wifi_mgmt_raise_connect_result_event(sidev->iface, WIFI_STATUS_CONN_SUCCESS);
	sidev->state = WIFI_STATE_COMPLETED;

	if (IS_ENABLED(CONFIG_WIFI_SIWX917_NET_STACK_NATIVE)) {
		net_eth_carrier_on(sidev->iface);
	}

	siwx917_on_join_ipv4(sidev);
	siwx917_on_join_ipv6(sidev);

	return SL_STATUS_OK;
}

static int siwx917_connect(const struct device *dev, struct wifi_connect_req_params *params)
{
	sl_wifi_client_configuration_t wifi_config = {
		.bss_type = SL_WIFI_BSS_TYPE_INFRASTRUCTURE,
	};
	int ret;

	switch (params->security) {
	case WIFI_SECURITY_TYPE_NONE:
		wifi_config.security = SL_WIFI_OPEN;
		wifi_config.encryption = SL_WIFI_NO_ENCRYPTION;
		break;
	case WIFI_SECURITY_TYPE_WPA_PSK:
		wifi_config.security = SL_WIFI_WPA;
		wifi_config.encryption = SL_WIFI_DEFAULT_ENCRYPTION;
		wifi_config.credential_id = SL_NET_DEFAULT_WIFI_CLIENT_CREDENTIAL_ID;
		break;
	case WIFI_SECURITY_TYPE_PSK:
		wifi_config.security = SL_WIFI_WPA2;
		wifi_config.encryption = SL_WIFI_TKIP_ENCRYPTION;
		wifi_config.credential_id = SL_NET_DEFAULT_WIFI_CLIENT_CREDENTIAL_ID;
		break;
	case WIFI_SECURITY_TYPE_PSK_SHA256:
		wifi_config.security = SL_WIFI_WPA2;
		wifi_config.encryption = SL_WIFI_CCMP_ENCRYPTION;
		wifi_config.credential_id = SL_NET_DEFAULT_WIFI_CLIENT_CREDENTIAL_ID;
		break;
	case WIFI_SECURITY_TYPE_SAE:
		/* TODO: Support the case where MFP is not required */
		wifi_config.security = SL_WIFI_WPA3;
		wifi_config.credential_id = SL_NET_DEFAULT_WIFI_CLIENT_CREDENTIAL_ID;
		break;
	case WIFI_SECURITY_TYPE_WPA_AUTO_PERSONAL:
		wifi_config.security = SL_WIFI_WPA2;
		wifi_config.encryption = SL_WIFI_DEFAULT_ENCRYPTION;
		wifi_config.credential_id = SL_NET_DEFAULT_WIFI_CLIENT_CREDENTIAL_ID;
		break;
	/* Zephyr WiFi shell doesn't specify how to pass credential for these
	 * key managements.
	 */
	case WIFI_SECURITY_TYPE_WEP: /* SL_WIFI_WEP/SL_WIFI_WEP_ENCRYPTION */
	case WIFI_SECURITY_TYPE_EAP: /* SL_WIFI_WPA2_ENTERPRISE/<various> */
	case WIFI_SECURITY_TYPE_WAPI:
	default:
		return -ENOTSUP;
	}

	if (params->band != WIFI_FREQ_BAND_UNKNOWN && params->band != WIFI_FREQ_BAND_2_4_GHZ) {
		return -ENOTSUP;
	}

	if (params->psk_length) {
		sl_net_set_credential(SL_NET_DEFAULT_WIFI_CLIENT_CREDENTIAL_ID, SL_NET_WIFI_PSK,
				      params->psk, params->psk_length);
	}

	if (params->sae_password_length) {
		sl_net_set_credential(SL_NET_DEFAULT_WIFI_CLIENT_CREDENTIAL_ID, SL_NET_WIFI_PSK,
				      params->sae_password, params->sae_password_length);
	}

	if (params->channel != WIFI_CHANNEL_ANY) {
		wifi_config.channel.channel = params->channel;
	}

	wifi_config.ssid.length = params->ssid_length,
	memcpy(wifi_config.ssid.value, params->ssid, params->ssid_length);

	ret = sl_wifi_connect(SL_WIFI_CLIENT_INTERFACE, &wifi_config, 0);
	if (ret != SL_STATUS_IN_PROGRESS) {
		return ERROR_CODE_CHECK(ret);
	}

	return 0;
}

static int siwx917_disconnect(const struct device *dev)
{
	struct siwx917_dev *sidev = dev->data;
	int ret;

	ret = sl_wifi_disconnect(SL_WIFI_CLIENT_INTERFACE);
	if (ret) {
		return ERROR_CODE_CHECK(ret);
	}
	if (IS_ENABLED(CONFIG_WIFI_SIWX917_NET_STACK_NATIVE)) {
		net_eth_carrier_off(sidev->iface);
	}
	sidev->state = WIFI_STATE_INACTIVE;
	return 0;
}

static void siwx917_report_scan_res(struct siwx917_dev *sidev, sl_wifi_scan_result_t *result,
				    int item)
{
	static const struct {
		int sl_val;
		int z_val;
	} security_convert[] = {
		{ SL_WIFI_OPEN,            WIFI_SECURITY_TYPE_NONE    },
		{ SL_WIFI_WEP,             WIFI_SECURITY_TYPE_WEP     },
		{ SL_WIFI_WPA,             WIFI_SECURITY_TYPE_WPA_PSK },
		{ SL_WIFI_WPA2,            WIFI_SECURITY_TYPE_PSK     },
		{ SL_WIFI_WPA3,            WIFI_SECURITY_TYPE_SAE     },
		{ SL_WIFI_WPA3_TRANSITION, WIFI_SECURITY_TYPE_SAE     },
		{ SL_WIFI_WPA_ENTERPRISE,  WIFI_SECURITY_TYPE_EAP     },
		{ SL_WIFI_WPA2_ENTERPRISE, WIFI_SECURITY_TYPE_EAP     },
	};
	struct wifi_scan_result tmp = {
		.channel = result->scan_info[item].rf_channel,
		.rssi = result->scan_info[item].rssi_val,
		.ssid_length = strlen(result->scan_info[item].ssid),
		.mac_length = sizeof(result->scan_info[item].bssid),
		.security = WIFI_SECURITY_TYPE_UNKNOWN,
		.mfp = WIFI_MFP_UNKNOWN,
		/* FIXME: fill .mfp, .band and .channel */
	};
	int i;

	memcpy(tmp.ssid, result->scan_info[item].ssid, tmp.ssid_length);
	memcpy(tmp.mac, result->scan_info[item].bssid, tmp.mac_length);
	for (i = 0; i < ARRAY_SIZE(security_convert); i++) {
		if (security_convert[i].sl_val == result->scan_info[item].security_mode) {
			tmp.security = security_convert[i].z_val;
		}
	}
	sidev->scan_res_cb(sidev->iface, 0, &tmp);
}

static unsigned int siwx917_on_scan(sl_wifi_event_t event, sl_wifi_scan_result_t *result,
				    uint32_t result_size, void *arg)
{
	struct siwx917_dev *sidev = arg;
	int i;

	if (!sidev->scan_res_cb) {
		return -EFAULT;
	}
	for (i = 0; i < result->scan_count; i++) {
		siwx917_report_scan_res(sidev, result, i);
	}
	sidev->scan_res_cb(sidev->iface, 0, NULL);
	sidev->state = WIFI_STATE_INACTIVE;
	return 0;
}

static int siwx917_scan(const struct device *dev, struct wifi_scan_params *z_scan_config,
			scan_result_cb_t cb)
{
	sl_wifi_scan_configuration_t sl_scan_config = { };
	struct siwx917_dev *sidev = dev->data;
	int ret;

	__ASSERT(z_scan_config, "z_scan_config cannot be NULL");

	if (sidev->state != WIFI_STATE_INACTIVE) {
		return -EBUSY;
	}

	/* The enum values are same, no conversion needed */
	sl_scan_config.type = z_scan_config->scan_type;

	sl_scan_config.channel_bitmap_2g4 = 0xFFFF;
	memset(sl_scan_config.channel_bitmap_5g, 0xFF, sizeof(sl_scan_config.channel_bitmap_5g));

	sidev->scan_res_cb = cb;
	ret = sl_wifi_start_scan(SL_WIFI_CLIENT_INTERFACE, NULL, &sl_scan_config);
	if (ret != SL_STATUS_IN_PROGRESS) {
		return ERROR_CODE_CHECK(ret);
	}
	sidev->state = WIFI_STATE_SCANNING;

	return 0;
}

static int siwx917_status(const struct device *dev, struct wifi_iface_status *status)
{
	struct siwx917_dev *sidev = dev->data;
	sl_si91x_rsp_wireless_info_t info = {};
	sl_wifi_rate_t mask = {0};
	int ret;
	int32_t rssi = -1;

	memset(status, 0, sizeof(*status));
	status->state = sidev->state;

	ret = sl_wifi_get_wireless_info(&info);
	if (ret) {
		LOG_ERR("Failed to get the wireless info: 0x%x", ret);
		return ERROR_CODE_CHECK(ret);
	}

	strncpy(status->ssid, info.ssid, WIFI_SSID_MAX_LEN);
	status->ssid_len = strnlen(info.ssid, WIFI_SSID_MAX_LEN);
	status->ssid[status->ssid_len] = '\0';
	memcpy(status->bssid, info.mac_address, WIFI_MAC_ADDR_LEN);
	status->mfp = WIFI_MFP_REQUIRED;

	if (sidev->interface & SL_WIFI_2_4GHZ_INTERFACE) {
		status->band = WIFI_FREQ_BAND_2_4_GHZ;
	}

	if (sidev->interface & SL_WIFI_CLIENT_INTERFACE) {
		sl_wifi_listen_interval_t listen_interval = {};

		status->link_mode = WIFI_LINK_MODE_UNKNOWN;
		status->iface_mode = WIFI_MODE_INFRA;
		status->channel = info.channel_number;
		sl_wifi_get_signal_strength(SL_WIFI_CLIENT_INTERFACE, &rssi);
		status->rssi = rssi;

		sl_wifi_get_listen_interval(SL_WIFI_CLIENT_INTERFACE, &listen_interval);
		status->beacon_interval = listen_interval.listen_interval;

		get_saved_sl_wifi_rate(&mask);
		status->current_phy_tx_rate = get_sl_wifi_rate_mbps(mask);
	} else if (sidev->interface & SL_WIFI_AP_INTERFACE) {
		sl_wifi_ap_configuration_t conf = {};

		ret = sl_wifi_get_ap_configuration(SL_WIFI_AP_INTERFACE, &conf);
		if (ret) {
			LOG_ERR("Failed to get the AP configuration: 0x%x", ret);
			return ERROR_CODE_CHECK(ret);
		}

		status->link_mode = WIFI_4;
		status->iface_mode = WIFI_MODE_AP;
		status->channel = conf.channel.channel;
		status->beacon_interval = conf.beacon_interval;
		status->dtim_period = conf.dtim_beacon_count;
	} else {
		status->link_mode = WIFI_LINK_MODE_UNKNOWN;
		status->iface_mode = WIFI_MODE_UNKNOWN;
		status->channel = 0;
	}

	switch (info.sec_type) {
	case SL_WIFI_OPEN:
		status->security = WIFI_SECURITY_TYPE_NONE;
		break;
	case SL_WIFI_WPA2:
		status->security = WIFI_SECURITY_TYPE_PSK;
		break;
	case SL_WIFI_WPA3:
		status->security = WIFI_SECURITY_TYPE_SAE;
		break;
	default:
		status->security = WIFI_SECURITY_TYPE_UNKNOWN;
	}

	return ret;
}

#ifdef CONFIG_WIFI_SIWX917_NET_STACK_NATIVE

static int siwx917_send(const struct device *dev, struct net_pkt *pkt)
{
	size_t pkt_len = net_pkt_get_len(pkt);
	struct net_buf *buf = NULL;
	int ret;

	if (net_pkt_get_len(pkt) > _NET_ETH_MAX_FRAME_SIZE) {
		LOG_ERR("unexpected buffer size");
		return -ENOBUFS;
	}
	buf = net_buf_alloc(&siwx917_tx_pool, K_FOREVER);
	if (!buf) {
		return -ENOBUFS;
	}
	if (net_pkt_read(pkt, buf->data, pkt_len)) {
		net_buf_unref(buf);
		return -ENOBUFS;
	}
	net_buf_add(buf, pkt_len);

	ret = sl_wifi_send_raw_data_frame(SL_WIFI_CLIENT_INTERFACE, buf->data, pkt_len);
	if (ret) {
		return ERROR_CODE_CHECK(ret);
	}

	net_pkt_unref(pkt);
	net_buf_unref(buf);

	return 0;
}

/* Receive callback. Keep the name as it is declared weak in WiseConnect */
sl_status_t sl_si91x_host_process_data_frame(sl_wifi_interface_t interface,
					     sl_wifi_buffer_t *buffer)
{
	sl_si91x_packet_t *si_pkt = sl_si91x_host_get_buffer_data(buffer, 0, NULL);
	struct net_if *iface = net_if_get_default();
	struct net_pkt *pkt;
	int ret;

	pkt = net_pkt_rx_alloc_with_buffer(iface, buffer->length, AF_UNSPEC, 0, K_NO_WAIT);
	if (!pkt) {
		LOG_ERR("net_pkt_rx_alloc_with_buffer() failed");
		return SL_STATUS_FAIL;
	}
	ret = net_pkt_write(pkt, si_pkt->data, si_pkt->length);
	if (ret < 0) {
		LOG_ERR("net_pkt_write(): %d", ret);
		goto unref;
	}
	ret = net_recv_data(iface, pkt);
	if (ret < 0) {
		LOG_ERR("net_recv_data((): %d", ret);
		goto unref;
	}
	return 0;

unref:
	net_pkt_unref(pkt);
	return SL_STATUS_FAIL;
}

#endif

static void siwx917_ethernet_init(struct net_if *iface)
{
	struct ethernet_context *eth_ctx;

	if (IS_ENABLED(CONFIG_WIFI_SIWX917_NET_STACK_NATIVE)) {
		eth_ctx = net_if_l2_data(iface);
		eth_ctx->eth_if_type = L2_ETH_IF_TYPE_WIFI;
		ethernet_init(iface);
	}
}

#ifdef CONFIG_WIFI_SIWX917_AP_MODE
static int siwx917_ap_enable(const struct device *dev, struct wifi_connect_req_params *params)
{
	struct siwx917_dev *sidev = dev->data;
	int ret;

	sl_wifi_ap_configuration_t configuration = {
		.channel = {
				.bandwidth = SL_WIFI_AUTO_BANDWIDTH,
				.channel = (params->channel == WIFI_CHANNEL_ANY)
						   ? SL_WIFI_AUTO_CHANNEL
						   : params->channel,
				.band = (params->band == WIFI_FREQ_BAND_2_4_GHZ)
						? SL_WIFI_BAND_2_4GHZ
						: SL_WIFI_AUTO_BAND,
			},
		.encryption = SL_WIFI_CCMP_ENCRYPTION,
		.rate_protocol = SL_WIFI_RATE_PROTOCOL_AUTO,
		.options = 0,
		.credential_id = SL_NET_DEFAULT_WIFI_AP_CREDENTIAL_ID,
		.keepalive_type = SL_SI91X_AP_NULL_BASED_KEEP_ALIVE,
		.beacon_interval = CONFIG_BEACON_INTERVAL,
		.client_idle_timeout = 0xFF,
		.dtim_beacon_count = CONFIG_DTIM_BEACON_COUNT,
		.maximum_clients = CONFIG_WIFI_MAX_STATIONS,
		.beacon_stop = 0,
		.tdi_flags = SL_WIFI_TDI_NONE,
		.is_11n_enabled = 1,
		.ssid = {
				.length = params->ssid_length,
			},
	};

	strncpy(configuration.ssid.value, params->ssid, params->ssid_length);

	switch (params->security) {
	case WIFI_SECURITY_TYPE_NONE:
		configuration.security = SL_WIFI_OPEN;
		break;

	case WIFI_SECURITY_TYPE_PSK:
		configuration.security = SL_WIFI_WPA2;
		sl_net_wifi_psk_credential_entry_t wifi_ap_credential = {
			.type = SL_NET_WIFI_PSK, .data_length = params->psk_length};

		strncpy(wifi_ap_credential.data, params->psk, params->psk_length);

		ret = sl_net_set_credential(SL_NET_DEFAULT_WIFI_AP_CREDENTIAL_ID,
					    wifi_ap_credential.type, &wifi_ap_credential.data,
					    wifi_ap_credential.data_length);
		if (ret) {
			LOG_ERR("Failed to set credentials: 0x%x", ret);
			return ERROR_CODE_CHECK(ret);
		}

		configuration.credential_id = SL_NET_DEFAULT_WIFI_AP_CREDENTIAL_ID;
		break;
	default:
		LOG_ERR("Unsupported security type");
		return -EINVAL;
	}

	ret = sl_wifi_start_ap(SL_WIFI_AP_2_4GHZ_INTERFACE, &configuration);
	if (ret) {
		LOG_ERR("Failed to enable AP mode: 0x%x", ret);
		return ERROR_CODE_CHECK(ret);
	}

	sidev->state = WIFI_STATE_COMPLETED;
	return ret;
}

static int siwx917_ap_disable(const struct device *dev)
{
	struct siwx917_dev *sidev = dev->data;
	int ret;

	ret = sl_wifi_stop_ap(SL_WIFI_AP_2_4GHZ_INTERFACE);
	if (ret) {
		LOG_ERR("Failed to disable Wi-Fi AP mode: 0x%x", ret);
		return ERROR_CODE_CHECK(ret);
	}

	sidev->state = WIFI_STATE_INTERFACE_DISABLED;
	return ret;
}

static int siwx917_ap_sta_disconnect(const struct device *dev, const uint8_t *mac_addr)
{
	sl_mac_address_t mac = {};
	int ret;

	if (!mac_addr) {
		return -EINVAL;
	}

	strncpy(mac.octet, mac_addr, sizeof(mac.octet));

	ret = sl_wifi_disconnect_ap_client(SL_WIFI_AP_2_4GHZ_INTERFACE, &mac, SL_WIFI_DEAUTH);
	if (ret) {
		LOG_ERR("Failed	to disconnect: 0x%x", ret);
		return ERROR_CODE_CHECK(ret);
	}

	return ret;
}

static sl_status_t ap_connected_event_handler(sl_wifi_event_t event, void *data,
					      uint32_t data_length, void *arg)
{
	ARG_UNUSED(event);

	struct siwx917_dev *sidev = arg;
	struct wifi_ap_sta_info sta_info = {};

	strncpy(sta_info.mac, (uint8_t *)data, data_length);
	sta_info.mac_length = data_length;
	sta_info.link_mode = WIFI_LINK_MODE_UNKNOWN;

	wifi_mgmt_raise_ap_sta_connected_event(sidev->iface, &sta_info);

	return SL_STATUS_OK;
}

static sl_status_t ap_disconnected_event_handler(sl_wifi_event_t event, void *data,
						 uint32_t data_length, void *arg)
{
	ARG_UNUSED(event);

	struct siwx917_dev *sidev = arg;
	struct wifi_ap_sta_info sta_info = {};

	memcpy(sta_info.mac, (uint8_t *)data, data_length);
	sta_info.mac_length = data_length;
	wifi_mgmt_raise_ap_sta_disconnected_event(sidev->iface, &sta_info);

	return SL_STATUS_OK;
}
#endif

#if defined(CONFIG_NET_STATISTICS_WIFI)
static int siwx917_wifi_stats(const struct device *dev, struct net_stats_wifi *stats)
{
	struct siwx917_dev *sidev = dev->data;
	sl_wifi_statistics_t statistics = {};
	int ret;

	ret = sl_wifi_get_statistics((sidev->interface & GET_INTERFACE), &statistics);
	if (ret) {
		LOG_ERR("Failed to get stat: 0x%x", ret);
		return ERROR_CODE_CHECK(ret);
	}

	stats->multicast.rx = statistics.mcast_rx_count;
	stats->multicast.tx = statistics.mcast_tx_count;
	stats->unicast.rx = statistics.ucast_rx_count;
	stats->unicast.tx = statistics.ucast_tx_count;
	stats->sta_mgmt.beacons_rx = statistics.beacon_rx_count;
	stats->sta_mgmt.beacons_miss = statistics.beacon_lost_count;
	stats->overrun_count = statistics.overrun_count;

	return ret;
}
#endif

static void siwx917_iface_init(struct net_if *iface)
{
	struct siwx917_dev *sidev = iface->if_dev->dev->data;
	sl_status_t status;

	sidev->state = WIFI_STATE_INTERFACE_DISABLED;
	sidev->iface = iface;

	sl_wifi_set_scan_callback(siwx917_on_scan, sidev);
	sl_wifi_set_join_callback(siwx917_on_join, sidev);

	sidev->interface = sl_wifi_get_default_interface();

#ifdef CONFIG_WIFI_SIWX917_AP_MODE
	sl_wifi_set_callback(SL_WIFI_CLIENT_CONNECTED_EVENTS, ap_connected_event_handler, sidev);
	sl_wifi_set_callback(SL_WIFI_CLIENT_DISCONNECTED_EVENTS, ap_disconnected_event_handler,
			     sidev);
#endif
	status = sl_wifi_get_mac_address((sidev->interface & GET_INTERFACE), &sidev->macaddr);
	if (status) {
		LOG_ERR("sl_wifi_get_mac_address(): %#04x", status);
		return;
	}
	net_if_set_link_addr(iface, sidev->macaddr.octet, sizeof(sidev->macaddr.octet),
			     NET_LINK_ETHERNET);
	siwx917_sock_init(iface);
	siwx917_ethernet_init(iface);

	sidev->state = WIFI_STATE_INACTIVE;
}

static int siwx917_dev_init(const struct device *dev)
{
	return 0;
}

static const struct wifi_mgmt_ops siwx917_mgmt = {
	.scan         = siwx917_scan,
	.connect      = siwx917_connect,
	.disconnect   = siwx917_disconnect,

#ifdef CONFIG_WIFI_SIWX917_AP_MODE
	.ap_enable = siwx917_ap_enable,
	.ap_disable = siwx917_ap_disable,
	.ap_sta_disconnect = siwx917_ap_sta_disconnect,
#endif
	.iface_status = siwx917_status,
#if defined(CONFIG_NET_STATISTICS_WIFI)
	.get_stats = siwx917_wifi_stats,
#endif
};

static const struct net_wifi_mgmt_offload siwx917_api = {
	.wifi_iface.iface_api.init = siwx917_iface_init,
#ifdef CONFIG_WIFI_SIWX917_NET_STACK_NATIVE
	.wifi_iface.send = siwx917_send,
#else
	.wifi_iface.get_type = siwx917_get_type,
#endif
	.wifi_mgmt_api = &siwx917_mgmt,
};

static struct siwx917_dev siwx917_dev;
#ifdef CONFIG_WIFI_SIWX917_NET_STACK_NATIVE
ETH_NET_DEVICE_DT_INST_DEFINE(0, siwx917_dev_init, NULL, &siwx917_dev, NULL,
			      CONFIG_WIFI_INIT_PRIORITY, &siwx917_api, NET_ETH_MTU);
#else
NET_DEVICE_DT_INST_OFFLOAD_DEFINE(0, siwx917_dev_init, NULL, &siwx917_dev, NULL,
				  CONFIG_WIFI_INIT_PRIORITY, &siwx917_api, NET_ETH_MTU);
#endif
