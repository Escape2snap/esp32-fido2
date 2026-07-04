/*
 * ESP32-FIDO2 — Device configuration
 * Edit these to customize your device name, manufacturer, URLs, etc.
 */
#ifndef DEVICE_CONFIG_H
#define DEVICE_CONFIG_H

// USB Manufacturer string (index 1)
#define DEVICE_MANUFACTURER  "ESP32Key"

// USB Product string (index 2)
#define DEVICE_PRODUCT       "ESP32Key"

// USB Vendor ID (default: Raspberry Pi / Pol Henarejos)
#define DEVICE_VID           0x2E8A

// USB Product ID
#define DEVICE_PID           0x10FF

// WebUSB URL (shown in browser when requesting WebUSB access)
#define DEVICE_URL           "github.com/Escape2snap/esp32-fido2"

// Interface name strings
#define DEVICE_IFACE_HID     "ESP32Key HID"
#define DEVICE_IFACE_CCID    "ESP32Key CCID"
#define DEVICE_IFACE_WCID    "ESP32Key WebCCID"
#define DEVICE_IFACE_NET     "ESP32Key Network"
#define DEVICE_IFACE_KB      "ESP32Key Keyboard"

// Attestation certificate organization
#define DEVICE_CERT_ORG      "ESP32Key"
#define DEVICE_CERT_CN_PIV   "ESP32Key PIV"
#define DEVICE_CERT_CN_EE    "ESP32Key EE"

#endif // DEVICE_CONFIG_H
