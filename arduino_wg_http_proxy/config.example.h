#pragma once

#include <IPAddress.h>

// Copy this file to config.h and replace the example values.
static const char WIFI_SSID[] = "YOUR_WIFI_NAME";
static const char WIFI_PASSWORD[] = "YOUR_WIFI_PASSWORD";

static const char WG_PRIVATE_KEY[] = "YOUR_ESP32_PRIVATE_KEY_BASE64";
static const IPAddress WG_TUNNEL_IP(10, 77, 0, 2);
static const char WG_SERVER_PUBLIC_KEY[] = "YOUR_VPS_PUBLIC_KEY_BASE64";
static const char WG_ENDPOINT_HOST[] = "YOUR_VPS_PUBLIC_IP_OR_HOSTNAME";
static const uint16_t WG_ENDPOINT_PORT = 51820;

static const uint16_t HTTP_PROXY_PORT = 8080;
