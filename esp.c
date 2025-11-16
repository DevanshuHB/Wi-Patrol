#include "WiFi.h"

// ========== CONFIG ==========
const int SCAN_INTERVAL = 10000;  // 10 seconds
const char* WHITELIST[][6] = {
  // SSID, BSSID, RSSI, Channel, Encryption, Status
  {"Home_Network", "AA:BB:CC:DD:EE:FF", "-45", "6", "WPA2", "Known: Safe"},
  {"College_WiFi", "11:22:33:44:55:66", "-60", "11", "WPA2", "Known: Safe"}
};
const int WHITELIST_COUNT = sizeof(WHITELIST) / sizeof(WHITELIST[0]);
// ============================

// ---------- Helper: Convert Encryption Type ----------
String encryptionType(wifi_auth_mode_t type) {
  switch (type) {
    case WIFI_AUTH_OPEN: return "Open";
    case WIFI_AUTH_WEP: return "WEP";
    case WIFI_AUTH_WPA_PSK: return "WPA";
    case WIFI_AUTH_WPA2_PSK: return "WPA2";
    case WIFI_AUTH_WPA_WPA2_PSK: return "WPA/WPA2";
    case WIFI_AUTH_WPA2_ENTERPRISE: return "WPA2-ENT";
    case WIFI_AUTH_WPA3_PSK: return "WPA3";
    case WIFI_AUTH_WPA2_WPA3_PSK: return "WPA2/WPA3";
    default: return "Unknown";
  }
}

// ---------- Helper: Classification ----------
String classifyNetwork(String ssid, String bssid, String encryption) {
  // Check if in whitelist
  for (int i = 0; i < WHITELIST_COUNT; i++) {
    if (ssid.equalsIgnoreCase(WHITELIST[i][0]) && bssid.equalsIgnoreCase(WHITELIST[i][1])) {
      return "Known: Safe";
    }
  }

  // Suspicious encryption
  if (encryption == "Open" || encryption == "WEP" || encryption == "WPA") {
    return "Unknown: Suspicious";
  }

  // Suspicious SSID patterns
  String ssidLower = ssid;
  ssidLower.toLowerCase();
  if (ssidLower.indexOf("free") >= 0 || ssidLower.indexOf("guest") >= 0 ||
      ssidLower.indexOf("public") >= 0 || ssidLower.indexOf("fake") >= 0) {
    return "Unknown: Suspicious";
  }

  // Default safe
  return "Unknown: Safe";
}

// ---------- Setup ----------
void setup() {
  Serial.begin(115200);
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(100);
  Serial.println("===== Wi-Patrol Network Scanner Started =====");
}

// ---------- Loop ----------
void loop() {
  Serial.println("\nScanning nearby WiFi networks...");
  int n = WiFi.scanNetworks(false, true); // async=false, show_hidden=true

  if (n == 0) {
    Serial.println("No networks found.");
  } else {
    Serial.printf("Found %d networks:\n", n);
    Serial.println("---------------------------------------------------------------");
    Serial.println("SSID\t\tBSSID\t\tRSSI\tCH\tEncrypt\t\tStatus");
    Serial.println("---------------------------------------------------------------");

    for (int i = 0; i < n; i++) {
      String ssid = WiFi.SSID(i);
      String bssid = WiFi.BSSIDstr(i);
      int rssi = WiFi.RSSI(i);
      int channel = WiFi.channel(i);
      String encryption = encryptionType(WiFi.encryptionType(i));
      String status = classifyNetwork(ssid, bssid, encryption);

      Serial.printf("%-15s %-18s %-4d\t%-2d\t%-10s %-20s\n",
                    ssid.c_str(), bssid.c_str(), rssi, channel, encryption.c_str(), status.c_str());
    }
  }

  WiFi.scanDelete(); // free memory
  delay(SCAN_INTERVAL);
}
