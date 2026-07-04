/*
 * ESP32-FIDO2 — Device configuration template
 * Copy to device_config.h and edit to customize.
 */
#ifndef DEVICE_CONFIG_H
#define DEVICE_CONFIG_H

// USB Manufacturer string
#define DEVICE_MANUFACTURER  "ESP32 Key"

// USB Product string
#define DEVICE_PRODUCT       "ESP32 Key"

// USB Vendor ID
#define DEVICE_VID           0x2E8A

// USB Product ID
#define DEVICE_PID           0x10FF

// WebUSB URL
#define DEVICE_URL           "github.com/Escape2snap/esp32-fido2"

// Interface name strings
#define DEVICE_IFACE_HID     "HID Interface"
#define DEVICE_IFACE_CCID    "CCID OTP FIDO Interface"
#define DEVICE_IFACE_WCID    "WebCCID Interface"
#define DEVICE_IFACE_NET     "Network Interface"
#define DEVICE_IFACE_KB      "HID Keyboard Interface"

#endif // DEVICE_CONFIG_H
