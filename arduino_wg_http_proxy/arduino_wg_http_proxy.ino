#include <WiFi.h>
#include <WireGuard-ESP32.h>
#include <ping/ping_sock.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#include <freertos/task.h>
#include <esp_heap_caps.h>
#include <new>
#include <time.h>
#include <strings.h>

#include "miniz_config.h"
#include "miniz.h"
#include "config.h"

static constexpr uint32_t WIFI_RETRY_INTERVAL_MS = 15000;
static constexpr uint32_t TIME_SYNC_TIMEOUT_MS = 30000;
static constexpr uint32_t CLIENT_HEADER_TIMEOUT_MS = 10000;
static constexpr uint32_t UPSTREAM_IDLE_TIMEOUT_MS = 15000;
static constexpr uint32_t CONNECT_IDLE_TIMEOUT_MS = 300000;
static constexpr uint32_t WEBSOCKET_IDLE_TIMEOUT_MS = 3600000;
static constexpr uint32_t TARGET_CONNECT_TIMEOUT_MS = 1500;
static constexpr size_t MAX_PROXY_CLIENTS = 4;
static constexpr uint32_t PROXY_CLIENT_STACK_SIZE = 12288;
static constexpr size_t REQUEST_HEADER_CAPACITY = 2048;
static constexpr size_t REQUEST_LINE_CAPACITY = 512;
static constexpr size_t HOST_CAPACITY = 128;
static constexpr size_t PATH_CAPACITY = 512;
static constexpr uint32_t MAX_REQUEST_BODY_BYTES = 2 * 1024 * 1024;
static constexpr uint16_t HTTP_SCAN_PORT = 8081;
static constexpr size_t SCAN_BATCH_SIZE = 16;
static constexpr size_t MAX_SCAN_HOSTS = 510;
static constexpr uint32_t SCAN_PING_TIMEOUT_MS = 250;
static constexpr size_t COMPRESSED_BLOCK_SIZE = 1024;
static constexpr size_t COMPRESSED_FRAME_MAX = 1024;
static constexpr size_t COMPRESSED_FRAME_HEADER_SIZE = 8;
static constexpr char COMPRESSED_CONNECT_HEADER[] = "X-ESP32-Proxy-Compression";
static constexpr char COMPRESSED_CONNECT_VALUE[] = "zlib-block-v1";

struct CompressionCodec {
  tdefl_compressor *deflater;
  tinfl_decompressor *inflater;
};

struct CompressionFrameReader {
  uint8_t header[COMPRESSED_FRAME_HEADER_SIZE];
  uint8_t payload[COMPRESSED_FRAME_MAX];
  size_t headerUsed;
  size_t payloadUsed;
  uint16_t encodedLength;
  uint16_t decodedLength;
  uint8_t type;
};

struct CompressionRelayBuffers {
  CompressionFrameReader clientReader;
  uint8_t decoded[COMPRESSED_BLOCK_SIZE];
};

static WireGuard wireGuard;
static WiFiServer proxyServer(HTTP_PROXY_PORT);
static WiFiServer scanServer(HTTP_SCAN_PORT);
static IPAddress scanResults[MAX_SCAN_HOSTS];
static size_t scanResultCount = 0;
static bool wireGuardStarted = false;
static bool proxyStarted = false;
static bool timeSyncStarted = false;
static uint32_t nextWifiAttemptAt = 0;
static uint32_t timeSyncStartedAt = 0;
static portMUX_TYPE proxyClientMux = portMUX_INITIALIZER_UNLOCKED;
static size_t activeProxyClients = 0;

struct ProxyClientTaskContext {
  WiFiClient client;
};

static void proxyClientTask(void *argument);

static bool timeReached(uint32_t deadline) {
  return static_cast<int32_t>(millis() - deadline) >= 0;
}

static void stopNetworkServices() {
  if (proxyStarted) {
    proxyServer.end();
    proxyStarted = false;
  }
  if (wireGuardStarted) {
    wireGuard.end();
    wireGuardStarted = false;
  }
  timeSyncStarted = false;
}

static bool waitForSystemTime() {
  if (!timeSyncStarted) {
    configTime(0, 0, "pool.ntp.org", "time.cloudflare.com");
    timeSyncStartedAt = millis();
    timeSyncStarted = true;
    Serial.println("Waiting for NTP time before starting WireGuard...");
  }

  if (time(nullptr) >= 1700000000) {
    return true;
  }
  if (millis() - timeSyncStartedAt >= TIME_SYNC_TIMEOUT_MS) {
    Serial.println("NTP time is not available yet; will retry.");
    timeSyncStarted = false;
  }
  return false;
}

static void maintainNetwork() {
  if (WiFi.status() != WL_CONNECTED) {
    if (wireGuardStarted || proxyStarted) {
      Serial.println("Wi-Fi lost; stopping proxy and WireGuard.");
      stopNetworkServices();
    }
    if (timeReached(nextWifiAttemptAt)) {
      Serial.println("Attempting Wi-Fi connection...");
      WiFi.disconnect(false, false);
      WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
      nextWifiAttemptAt = millis() + WIFI_RETRY_INTERVAL_MS;
    }
    return;
  }

  if (wireGuardStarted || !waitForSystemTime()) {
    return;
  }

  Serial.print("Wi-Fi connected at ");
  Serial.println(WiFi.localIP());
  Serial.println("Starting WireGuard (default persistent keepalive: 10 seconds)...");
  if (!wireGuard.begin(WG_TUNNEL_IP, WG_PRIVATE_KEY, WG_ENDPOINT_HOST,
                       WG_SERVER_PUBLIC_KEY, WG_ENDPOINT_PORT)) {
    Serial.println("WireGuard initialization failed; retrying.");
    timeSyncStarted = false;
    return;
  }

  wireGuardStarted = true;
  proxyServer.begin();
  proxyStarted = true;
  Serial.print("HTTP proxy listening on port ");
  Serial.println(HTTP_PROXY_PORT);
  Serial.print("WireGuard address: ");
  Serial.println(WG_TUNNEL_IP);
  Serial.println("Proxy accepts clients on Wi-Fi and WireGuard interfaces.");
}

static bool readHeader(WiFiClient &client, char *buffer, size_t capacity) {
  size_t used = 0;
  uint8_t matched = 0;
  const uint32_t startedAt = millis();

  while (millis() - startedAt < CLIENT_HEADER_TIMEOUT_MS) {
    while (client.available()) {
      const char value = static_cast<char>(client.read());
      if (used + 1 >= capacity) {
        return false;
      }
      buffer[used++] = value;
      buffer[used] = '\0';

      if ((matched == 0 && value == '\r') ||
          (matched == 1 && value == '\n') ||
          (matched == 2 && value == '\r') ||
          (matched == 3 && value == '\n')) {
        ++matched;
        if (matched == 4) {
          return true;
        }
      } else {
        matched = value == '\r' ? 1 : 0;
      }
    }
    if (!client.connected()) {
      return false;
    }
    delay(1);
  }
  return false;
}

static bool parsePort(const char *text, uint16_t *port) {
  if (text == nullptr || *text == '\0') {
    return false;
  }
  uint32_t value = 0;
  for (const char *digit = text; *digit; ++digit) {
    if (*digit < '0' || *digit > '9') {
      return false;
    }
    value = value * 10 + static_cast<uint32_t>(*digit - '0');
    if (value > 65535) {
      return false;
    }
  }
  if (value == 0) {
    return false;
  }
  *port = static_cast<uint16_t>(value);
  return true;
}

static bool parseAuthority(const char *authority, uint16_t defaultPort,
                           char *host, size_t hostCapacity, uint16_t *port) {
  if (authority == nullptr || *authority == '\0' || strchr(authority, '[')) {
    return false;
  }

  const char *colon = strrchr(authority, ':');
  size_t hostLength = strlen(authority);
  *port = defaultPort;
  if (colon != nullptr) {
    hostLength = static_cast<size_t>(colon - authority);
    if (memchr(authority, ':', hostLength) != nullptr ||
        !parsePort(colon + 1, port)) {
      return false;
    }
  } else if (defaultPort == 0) {
    return false;
  }
  if (hostLength == 0 || hostLength >= hostCapacity) {
    return false;
  }
  for (size_t index = 0; index < hostLength; ++index) {
    const char value = authority[index];
    if (value <= 32 || value == '/' || value == '\\' || value == '@' ||
        value == '#') {
      return false;
    }
  }
  memcpy(host, authority, hostLength);
  host[hostLength] = '\0';
  return true;
}

static bool addressIsOnWifiSubnet(const IPAddress &address) {
  const IPAddress local = WiFi.localIP();
  const IPAddress mask = WiFi.subnetMask();
  bool sameSubnet = true;
  bool allZero = true;
  bool allOnes = true;
  for (size_t octet = 0; octet < 4; ++octet) {
    sameSubnet &= (address[octet] & mask[octet]) ==
                  (local[octet] & mask[octet]);
    allZero &= address[octet] == 0;
    allOnes &= address[octet] == 255;
  }
  return sameSubnet && !allZero && !allOnes && address != local &&
         address[0] < 224;
}

static bool resolveLocalHost(const char *host, IPAddress *address) {
  if (address->fromString(host)) {
    return addressIsOnWifiSubnet(*address);
  }
  if (WiFi.hostByName(host, *address) != 1) {
    return false;
  }
  return addressIsOnWifiSubnet(*address);
}

static void sendError(WiFiClient &client, uint16_t status,
                      const char *reason, const char *detail) {
  client.printf("HTTP/1.1 %u %s\r\n", status, reason);
  client.print("Connection: close\r\nContent-Type: text/plain\r\n");
  client.printf("Content-Length: %u\r\n\r\n%s\n",
                static_cast<unsigned>(strlen(detail) + 1), detail);
}

static bool writeAll(WiFiClient &client, const uint8_t *data, size_t length) {
  size_t sent = 0;
  while (sent < length) {
    const size_t count = client.write(data + sent, length - sent);
    if (count == 0) {
      return false;
    }
    sent += count;
  }
  return true;
}

static bool copyExact(WiFiClient &source, WiFiClient &destination,
                      uint32_t length) {
  uint8_t buffer[256];
  uint32_t remaining = length;
  uint32_t lastDataAt = millis();
  while (remaining > 0) {
    const int available = source.available();
    if (available > 0) {
      size_t count = static_cast<size_t>(available);
      if (count > sizeof(buffer)) {
        count = sizeof(buffer);
      }
      if (count > remaining) {
        count = remaining;
      }
      const int received = source.read(buffer, count);
      if (received <= 0 ||
          !writeAll(destination, buffer, static_cast<size_t>(received))) {
        return false;
      }
      remaining -= static_cast<uint32_t>(received);
      lastDataAt = millis();
    } else {
      if (!source.connected() ||
          millis() - lastDataAt >= UPSTREAM_IDLE_TIMEOUT_MS) {
        return false;
      }
      delay(1);
    }
  }
  return true;
}

static void relayUntilClosed(WiFiClient &client, WiFiClient &upstream,
                             uint32_t idleTimeoutMs) {
  uint8_t buffer[512];
  uint32_t lastDataAt = millis();
  while (client.connected() && millis() - lastDataAt < idleTimeoutMs) {
    bool movedData = false;
    while (client.available()) {
      const int count = client.read(buffer, sizeof(buffer));
      if (count <= 0 ||
          !writeAll(upstream, buffer, static_cast<size_t>(count))) {
        client.stop();
        break;
      }
      movedData = true;
    }
    while (upstream.available()) {
      const int count = upstream.read(buffer, sizeof(buffer));
      if (count <= 0 ||
          !writeAll(client, buffer, static_cast<size_t>(count))) {
        upstream.stop();
        break;
      }
      movedData = true;
    }
    if (!upstream.connected() && !upstream.available()) {
      break;
    }
    if (movedData) {
      lastDataAt = millis();
    } else {
      delay(1);
    }
  }
}

static void *allocateCompressionState(size_t size) {
  void *memory = heap_caps_malloc(size, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  if (memory == nullptr) {
    memory = heap_caps_malloc(size, MALLOC_CAP_8BIT);
  }
  return memory;
}

static bool initializeCompression(CompressionCodec *codec) {
  memset(codec, 0, sizeof(*codec));
  codec->deflater = static_cast<tdefl_compressor *>(
      allocateCompressionState(sizeof(tdefl_compressor)));
  codec->inflater = static_cast<tinfl_decompressor *>(
      allocateCompressionState(sizeof(tinfl_decompressor)));
  if (codec->deflater == nullptr || codec->inflater == nullptr) {
    if (codec->deflater != nullptr) {
      heap_caps_free(codec->deflater);
    }
    if (codec->inflater != nullptr) {
      heap_caps_free(codec->inflater);
    }
    memset(codec, 0, sizeof(*codec));
    return false;
  }
  return true;
}

static void endCompression(CompressionCodec *codec) {
  heap_caps_free(codec->deflater);
  heap_caps_free(codec->inflater);
  memset(codec, 0, sizeof(*codec));
}

static bool writeCompressedFrame(WiFiClient &client, uint8_t type,
                                 const uint8_t *payload,
                                 uint16_t encodedLength,
                                 uint16_t decodedLength) {
  uint8_t header[COMPRESSED_FRAME_HEADER_SIZE] = {
      'E', 'C', 1, type,
      static_cast<uint8_t>(encodedLength >> 8),
      static_cast<uint8_t>(encodedLength),
      static_cast<uint8_t>(decodedLength >> 8),
      static_cast<uint8_t>(decodedLength)};
  return writeAll(client, header, sizeof(header)) &&
         writeAll(client, payload, encodedLength);
}

struct CompressionOutputBuffer {
  uint8_t *data;
  size_t capacity;
  size_t length;
};

static mz_bool appendCompressionOutput(const void *data, int length,
                                      void *userData) {
  CompressionOutputBuffer *output =
      static_cast<CompressionOutputBuffer *>(userData);
  if (length < 0 || static_cast<size_t>(length) > output->capacity - output->length) {
    return MZ_FALSE;
  }
  memcpy(output->data + output->length, data, static_cast<size_t>(length));
  output->length += static_cast<size_t>(length);
  return MZ_TRUE;
}

static bool sendCompressedData(WiFiClient &client, CompressionCodec *codec,
                               const uint8_t *data, uint16_t length) {
  uint8_t compressed[COMPRESSED_FRAME_MAX];
  const int flags = 1 | TDEFL_WRITE_ZLIB_HEADER | TDEFL_GREEDY_PARSING_FLAG;
  CompressionOutputBuffer output = {compressed, sizeof(compressed), 0};
  const tdefl_status initResult = tdefl_init(
      codec->deflater, appendCompressionOutput, &output, flags);
  const tdefl_status result =
      initResult == TDEFL_STATUS_OKAY
          ? tdefl_compress_buffer(codec->deflater, data, length, TDEFL_FINISH)
          : initResult;
  if (result == TDEFL_STATUS_DONE && output.length < length) {
    return writeCompressedFrame(client, 1, compressed,
                                static_cast<uint16_t>(output.length), length);
  }
  return writeCompressedFrame(client, 0, data, length, length);
}

static bool decodeCompressedFrame(CompressionCodec *codec,
                                  CompressionFrameReader *reader,
                                  uint8_t *decoded) {
  if (reader->type == 0) {
    memcpy(decoded, reader->payload, reader->decodedLength);
    return true;
  }

  tinfl_init(codec->inflater);
  size_t inputLength = reader->encodedLength;
  size_t outputLength = reader->decodedLength;
  const tinfl_status result = tinfl_decompress(
      codec->inflater, reader->payload, &inputLength, decoded, decoded,
      &outputLength,
      TINFL_FLAG_PARSE_ZLIB_HEADER | TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF |
          TINFL_FLAG_COMPUTE_ADLER32);
  return result == TINFL_STATUS_DONE &&
         inputLength == reader->encodedLength &&
         outputLength == reader->decodedLength;
}

static int readCompressedFrame(WiFiClient &source,
                               CompressionFrameReader *reader,
                               CompressionCodec *codec, uint8_t *decoded,
                               uint16_t *decodedLength) {
  while (source.available() > 0) {
    if (reader->headerUsed < sizeof(reader->header)) {
      size_t wanted = sizeof(reader->header) - reader->headerUsed;
      const int available = source.available();
      if (wanted > static_cast<size_t>(available)) {
        wanted = static_cast<size_t>(available);
      }
      const int count = source.read(reader->header + reader->headerUsed, wanted);
      if (count <= 0) {
        return -1;
      }
      reader->headerUsed += static_cast<size_t>(count);
      if (reader->headerUsed < sizeof(reader->header)) {
        continue;
      }

      if (reader->header[0] != 'E' || reader->header[1] != 'C' ||
          reader->header[2] != 1 || reader->header[3] > 1) {
        return -1;
      }
      reader->type = reader->header[3];
      reader->encodedLength =
          static_cast<uint16_t>(reader->header[4] << 8 | reader->header[5]);
      reader->decodedLength =
          static_cast<uint16_t>(reader->header[6] << 8 | reader->header[7]);
      if (reader->decodedLength == 0 ||
          reader->decodedLength > COMPRESSED_BLOCK_SIZE ||
          reader->encodedLength == 0 ||
          reader->encodedLength > COMPRESSED_FRAME_MAX ||
          (reader->type == 0 &&
           reader->encodedLength != reader->decodedLength)) {
        return -1;
      }
    }

    if (reader->payloadUsed < reader->encodedLength) {
      const int available = source.available();
      if (available <= 0) {
        return 0;
      }
      size_t wanted = reader->encodedLength - reader->payloadUsed;
      if (wanted > static_cast<size_t>(available)) {
        wanted = static_cast<size_t>(available);
      }
      const int count = source.read(reader->payload + reader->payloadUsed, wanted);
      if (count <= 0) {
        return -1;
      }
      reader->payloadUsed += static_cast<size_t>(count);
    }
    if (reader->payloadUsed == reader->encodedLength) {
      const bool valid = decodeCompressedFrame(codec, reader, decoded);
      *decodedLength = reader->decodedLength;
      reader->headerUsed = 0;
      reader->payloadUsed = 0;
      reader->encodedLength = 0;
      reader->decodedLength = 0;
      return valid ? 1 : -1;
    }
  }
  return 0;
}

static bool relayCompressedUntilClosed(WiFiClient &client,
                                       WiFiClient &upstream,
                                       CompressionCodec *codec,
                                       uint32_t idleTimeoutMs) {
  CompressionRelayBuffers *buffers = static_cast<CompressionRelayBuffers *>(
      allocateCompressionState(sizeof(CompressionRelayBuffers)));
  if (buffers == nullptr) {
    return false;
  }
  memset(buffers, 0, sizeof(*buffers));
  uint32_t lastDataAt = millis();
  bool successful = true;
  while (client.connected() && upstream.connected() &&
         millis() - lastDataAt < idleTimeoutMs) {
    bool movedData = false;
    while (client.available() > 0) {
      uint16_t decodedLength = 0;
      const int frameResult = readCompressedFrame(
          client, &buffers->clientReader, codec, buffers->decoded,
          &decodedLength);
      if (frameResult < 0 ||
          (frameResult > 0 &&
           !writeAll(upstream, buffers->decoded, decodedLength))) {
        successful = false;
        break;
      }
      movedData = true;
    }
    if (!successful) {
      break;
    }

    while (upstream.available() > 0) {
      const int count = upstream.read(buffers->decoded,
                  sizeof(buffers->decoded));
      if (count <= 0 ||
          !sendCompressedData(client, codec, buffers->decoded,
                              static_cast<uint16_t>(count))) {
        successful = false;
        break;
      }
      movedData = true;
    }
    if (!successful || (!upstream.connected() && !upstream.available())) {
      break;
    }
    if (movedData) {
      lastDataAt = millis();
    } else {
      delay(1);
    }
  }
  heap_caps_free(buffers);
  return successful;
}

static bool parseRequestLine(char *header, char *method, char *target,
                             char *version, char **headerLines) {
  char *lineEnd = strstr(header, "\r\n");
  if (lineEnd == nullptr) {
    return false;
  }
  *lineEnd = '\0';
  if (sscanf(header, "%15s %511s %15s", method, target, version) != 3) {
    return false;
  }
  *headerLines = lineEnd + 2;
  return true;
}

static bool getHeaderValue(char *headers, const char *name, char *value,
                           size_t valueCapacity) {
  char *line = headers;
  while (*line) {
    char *lineEnd = strstr(line, "\r\n");
    if (lineEnd == nullptr) {
      lineEnd = line + strlen(line);
    }
    char *colon = static_cast<char *>(memchr(line, ':', lineEnd - line));
    if (colon != nullptr && static_cast<size_t>(colon - line) == strlen(name) &&
        strncasecmp(line, name, strlen(name)) == 0) {
      char *start = colon + 1;
      while (start < lineEnd && (*start == ' ' || *start == '\t')) {
        ++start;
      }
      size_t length = static_cast<size_t>(lineEnd - start);
      while (length > 0 && (start[length - 1] == ' ' || start[length - 1] == '\t')) {
        --length;
      }
      if (length == 0 || length >= valueCapacity) {
        return false;
      }
      memcpy(value, start, length);
      value[length] = '\0';
      return true;
    }
    if (*lineEnd == '\0') {
      break;
    }
    line = lineEnd + 2;
  }
  return false;
}

static bool hasHeader(char *headers, const char *name) {
  char *line = headers;
  while (*line) {
    char *lineEnd = strstr(line, "\r\n");
    if (lineEnd == nullptr) {
      lineEnd = line + strlen(line);
    }
    char *colon = static_cast<char *>(memchr(line, ':', lineEnd - line));
    if (colon != nullptr && static_cast<size_t>(colon - line) == strlen(name) &&
        strncasecmp(line, name, strlen(name)) == 0) {
      return true;
    }
    if (*lineEnd == '\0') {
      break;
    }
    line = lineEnd + 2;
  }
  return false;
}

static bool hasConnectionToken(char *headers, const char *token) {
  char connection[128];
  if (!getHeaderValue(headers, "Connection", connection, sizeof(connection))) {
    return false;
  }

  char *start = connection;
  while (*start) {
    while (*start == ' ' || *start == '\t' || *start == ',') {
      ++start;
    }
    char *end = start;
    while (*end && *end != ',') {
      ++end;
    }
    char *trimmedEnd = end;
    while (trimmedEnd > start &&
           (trimmedEnd[-1] == ' ' || trimmedEnd[-1] == '\t')) {
      --trimmedEnd;
    }
    if (static_cast<size_t>(trimmedEnd - start) == strlen(token) &&
        strncasecmp(start, token, strlen(token)) == 0) {
      return true;
    }
    start = end;
  }
  return false;
}

static bool isWebSocketUpgrade(char *headers) {
  char upgrade[32];
  return getHeaderValue(headers, "Upgrade", upgrade, sizeof(upgrade)) &&
         strcasecmp(upgrade, "websocket") == 0 &&
         hasConnectionToken(headers, "Upgrade");
}

struct PingScanContext {
  volatile bool alive;
  SemaphoreHandle_t finished;
};

struct PingScanTarget {
  IPAddress address;
  PingScanContext context;
  esp_ping_handle_t handle;
  bool started;
};

static void onPingSuccess(esp_ping_handle_t, void *arguments) {
  PingScanContext *context = static_cast<PingScanContext *>(arguments);
  context->alive = true;
}

static void onPingEnd(esp_ping_handle_t, void *arguments) {
  PingScanContext *context = static_cast<PingScanContext *>(arguments);
  xSemaphoreGive(context->finished);
}

static uint32_t ipv4ToUint32(const IPAddress &address) {
  return (static_cast<uint32_t>(address[0]) << 24) |
         (static_cast<uint32_t>(address[1]) << 16) |
         (static_cast<uint32_t>(address[2]) << 8) |
         static_cast<uint32_t>(address[3]);
}

static IPAddress uint32ToIpv4(uint32_t address) {
  return IPAddress(static_cast<uint8_t>(address >> 24),
                   static_cast<uint8_t>(address >> 16),
                   static_cast<uint8_t>(address >> 8),
                   static_cast<uint8_t>(address));
}

static bool isContiguousMask(uint32_t mask) {
  bool sawZero = false;
  for (int bit = 31; bit >= 0; --bit) {
    const bool set = (mask & (1UL << bit)) != 0;
    if (sawZero && set) {
      return false;
    }
    sawZero |= !set;
  }
  return true;
}

static void startPingBatch(void *batchTargets, size_t count) {
  PingScanTarget *targets = static_cast<PingScanTarget *>(batchTargets);
  for (size_t index = 0; index < count; ++index) {
    PingScanTarget &target = targets[index];
    target.context.alive = false;
    target.context.finished = xSemaphoreCreateBinary();
    target.started = false;
    if (target.context.finished == nullptr) {
      continue;
    }

    esp_ping_config_t config = ESP_PING_DEFAULT_CONFIG();
    config.count = 1;
    config.interval_ms = 50;
    config.timeout_ms = SCAN_PING_TIMEOUT_MS;
    IP_ADDR4(&config.target_addr, target.address[0], target.address[1],
             target.address[2], target.address[3]);

    esp_ping_callbacks_t callbacks = {};
    callbacks.cb_args = &target.context;
    callbacks.on_ping_success = onPingSuccess;
    callbacks.on_ping_end = onPingEnd;
    if (esp_ping_new_session(&config, &callbacks, &target.handle) == ESP_OK &&
        esp_ping_start(target.handle) == ESP_OK) {
      target.started = true;
    } else if (target.handle != nullptr) {
      esp_ping_delete_session(target.handle);
      target.handle = nullptr;
    }
  }

  for (size_t index = 0; index < count; ++index) {
    PingScanTarget &target = targets[index];
    if (target.started) {
      if (xSemaphoreTake(target.context.finished,
                         pdMS_TO_TICKS(SCAN_PING_TIMEOUT_MS + 2000)) != pdTRUE) {
        esp_ping_stop(target.handle);
      }
      esp_ping_delete_session(target.handle);
      target.handle = nullptr;
      target.started = false;
      if (target.context.alive && scanResultCount < MAX_SCAN_HOSTS) {
        scanResults[scanResultCount++] = target.address;
      }
    }
    if (target.context.finished != nullptr) {
      vSemaphoreDelete(target.context.finished);
      target.context.finished = nullptr;
    }
  }
  vTaskDelay(pdMS_TO_TICKS(1100));
}

static bool scanWifiSubnet(uint32_t *scannedCount, uint8_t *prefixLength) {
  const IPAddress local = WiFi.localIP();
  const IPAddress mask = WiFi.subnetMask();
  const uint32_t localValue = ipv4ToUint32(local);
  const uint32_t maskValue = ipv4ToUint32(mask);
  if (!isContiguousMask(maskValue)) {
    return false;
  }

  uint8_t prefix = 0;
  for (int bit = 31; bit >= 0 && (maskValue & (1UL << bit)); --bit) {
    ++prefix;
  }
  const uint32_t network = localValue & maskValue;
  const uint32_t broadcast = network | ~maskValue;
  if (broadcast <= network + 1 || broadcast - network - 1 > MAX_SCAN_HOSTS) {
    return false;
  }

  *prefixLength = prefix;
  *scannedCount = 0;
  scanResultCount = 0;
  PingScanTarget batch[SCAN_BATCH_SIZE] = {};
  size_t batchCount = 0;

  for (uint32_t address = network + 1; address < broadcast; ++address) {
    if (address == localValue) {
      continue;
    }
    batch[batchCount++].address = uint32ToIpv4(address);
    ++*scannedCount;
    if (batchCount == SCAN_BATCH_SIZE) {
      startPingBatch(batch, batchCount);
      batchCount = 0;
    }
  }
  if (batchCount > 0) {
    startPingBatch(batch, batchCount);
  }
  return true;
}

static void formatIpv4(const IPAddress &address, char *output, size_t capacity) {
  snprintf(output, capacity, "%u.%u.%u.%u", address[0], address[1],
           address[2], address[3]);
}

static void handleInfoRequest(WiFiClient &client) {
  const bool wifiConnected = WiFi.status() == WL_CONNECTED;
  char localIp[16];
  char subnetMask[16];
  char gatewayIp[16];
  char wireGuardIp[16];
  formatIpv4(WiFi.localIP(), localIp, sizeof(localIp));
  formatIpv4(WiFi.subnetMask(), subnetMask, sizeof(subnetMask));
  formatIpv4(WiFi.gatewayIP(), gatewayIp, sizeof(gatewayIp));
  formatIpv4(WG_TUNNEL_IP, wireGuardIp, sizeof(wireGuardIp));

  char body[256];
  const int bodyLength = snprintf(
      body, sizeof(body),
      "{\"wifi_connected\":%s,\"local_ip\":\"%s\","
      "\"subnet_mask\":\"%s\",\"gateway_ip\":\"%s\","
      "\"wireguard_started\":%s,\"wireguard_ip\":\"%s\"}\n",
      wifiConnected ? "true" : "false", localIp, subnetMask, gatewayIp,
      wireGuardStarted ? "true" : "false", wireGuardIp);
  if (bodyLength < 0 || static_cast<size_t>(bodyLength) >= sizeof(body)) {
    sendError(client, 500, "Internal Server Error", "Could not format device info");
    return;
  }

  client.printf("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                "Cache-Control: no-store\r\nContent-Length: %u\r\n"
                "Connection: close\r\n\r\n",
                static_cast<unsigned>(bodyLength));
  client.write(reinterpret_cast<const uint8_t *>(body), bodyLength);
}

static void handleScanRequest(WiFiClient &client) {
  char requestHeader[REQUEST_HEADER_CAPACITY];
  if (!readHeader(client, requestHeader, sizeof(requestHeader))) {
    sendError(client, 408, "Request Timeout", "Could not read request headers");
    return;
  }

  char method[16];
  char target[REQUEST_LINE_CAPACITY];
  char version[16];
  char *headers;
  if (!parseRequestLine(requestHeader, method, target, version, &headers)) {
    sendError(client, 400, "Bad Request", "Malformed request line");
    return;
  }
  if (strcmp(method, "GET") != 0) {
    sendError(client, 405, "Method Not Allowed", "Use GET /info or GET /scan");
    return;
  }
  if (strcmp(target, "/info") == 0) {
    handleInfoRequest(client);
    return;
  }
  if (strcmp(target, "/scan") != 0) {
    sendError(client, 404, "Not Found", "Use GET /info or GET /scan");
    return;
  }

  uint32_t scannedCount;
  uint8_t prefixLength;
  if (!scanWifiSubnet(&scannedCount, &prefixLength)) {
    sendError(client, 422, "Unprocessable Content",
              "Wi-Fi subnet must be contiguous and no larger than /23");
    return;
  }

  char subnet[16];
  char prefix[64];
  char suffix[48];
  formatIpv4(uint32ToIpv4(ipv4ToUint32(WiFi.localIP()) &
                          ipv4ToUint32(WiFi.subnetMask())),
             subnet, sizeof(subnet));
  snprintf(prefix, sizeof(prefix), "{\"subnet\":\"%s/%u\",\"alive\":[",
           subnet, prefixLength);
  snprintf(suffix, sizeof(suffix), "],\"scanned\":%lu}\n",
           static_cast<unsigned long>(scannedCount));

  size_t bodyLength = strlen(prefix) + strlen(suffix);
  for (size_t index = 0; index < scanResultCount; ++index) {
    char address[16];
    formatIpv4(scanResults[index], address, sizeof(address));
    bodyLength += strlen(address) + 2 + (index > 0 ? 1 : 0);
  }

  client.printf("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                "Cache-Control: no-store\r\nContent-Length: %u\r\n"
                "Connection: close\r\n\r\n",
                static_cast<unsigned>(bodyLength));
  client.print(prefix);
  for (size_t index = 0; index < scanResultCount; ++index) {
    char address[16];
    formatIpv4(scanResults[index], address, sizeof(address));
    if (index > 0) {
      client.print(',');
    }
    client.printf("\"%s\"", address);
  }
  client.print(suffix);
}

static void scanServerTask(void *) {
  for (;;) {
    WiFiClient client = scanServer.available();
    if (client) {
      client.setTimeout(CLIENT_HEADER_TIMEOUT_MS);
      handleScanRequest(client);
      client.stop();
    }
    vTaskDelay(pdMS_TO_TICKS(5));
  }
}

static bool parseHttpTarget(const char *target, char *headers, char *host,
                            uint16_t *port, char *path) {
  const char *authority = nullptr;
  const char *pathStart = nullptr;
  size_t schemeLength = 0;
  if (strncasecmp(target, "http://", 7) == 0) {
    schemeLength = 7;
  } else if (strncasecmp(target, "ws://", 5) == 0) {
    schemeLength = 5;
  }
  if (schemeLength > 0) {
    authority = target + schemeLength;
    pathStart = strpbrk(authority, "/?#");
  }

  if (authority != nullptr) {
    char authorityCopy[HOST_CAPACITY + 8];
    const size_t authorityLength = pathStart == nullptr
                                       ? strlen(authority)
                                       : static_cast<size_t>(pathStart - authority);
    if (authorityLength == 0 || authorityLength >= sizeof(authorityCopy)) {
      return false;
    }
    memcpy(authorityCopy, authority, authorityLength);
    authorityCopy[authorityLength] = '\0';
    if (!parseAuthority(authorityCopy, 80, host, HOST_CAPACITY, port)) {
      return false;
    }
    if (pathStart == nullptr || *pathStart == '#') {
      strcpy(path, "/");
      return true;
    }
    const char *fragment = strchr(pathStart, '#');
    size_t pathLength = fragment == nullptr
                            ? strlen(pathStart)
                            : static_cast<size_t>(fragment - pathStart);
    if (*pathStart == '?') {
      if (pathLength + 2 > PATH_CAPACITY) {
        return false;
      }
      path[0] = '/';
      memcpy(path + 1, pathStart, pathLength);
      path[pathLength + 1] = '\0';
      return true;
    }
    if (pathLength == 0 || pathLength >= PATH_CAPACITY) {
      return false;
    }
    memcpy(path, pathStart, pathLength);
    path[pathLength] = '\0';
    return true;
  }

  char hostHeader[HOST_CAPACITY];
  if (!getHeaderValue(headers, "Host", hostHeader, sizeof(hostHeader)) ||
      !parseAuthority(hostHeader, 80, host, HOST_CAPACITY, port) ||
      target[0] != '/' || strlen(target) >= PATH_CAPACITY || strchr(target, '#')) {
    return false;
  }
  strcpy(path, target);
  return true;
}

static bool connectToLocalTarget(const char *host, uint16_t port,
                                 IPAddress *address, WiFiClient *upstream) {
  if (!resolveLocalHost(host, address)) {
    return false;
  }
  upstream->setTimeout(5000);
  upstream->setNoDelay(true);
  return upstream->connect(*address, port, TARGET_CONNECT_TIMEOUT_MS);
}

static void handleConnect(WiFiClient &client, const char *target,
                          bool compressedTunnel) {
  char host[HOST_CAPACITY];
  uint16_t port;
  if (!parseAuthority(target, 0, host, sizeof(host), &port)) {
    sendError(client, 400, "Bad Request", "CONNECT requires host:port");
    return;
  }

  IPAddress address;
  WiFiClient upstream;
  if (!connectToLocalTarget(host, port, &address, &upstream)) {
    sendError(client, 502, "Bad Gateway",
              "Target is unreachable or outside the local Wi-Fi subnet");
    return;
  }
  CompressionCodec codec;
  if (compressedTunnel && !initializeCompression(&codec)) {
    upstream.stop();
    sendError(client, 503, "Service Unavailable",
              "Could not initialize compression");
    return;
  }
  client.print("HTTP/1.1 200 Connection Established\r\n");
  if (compressedTunnel) {
    client.printf("%s: %s\r\n\r\n", COMPRESSED_CONNECT_HEADER,
                  COMPRESSED_CONNECT_VALUE);
    relayCompressedUntilClosed(client, upstream, &codec,
                               CONNECT_IDLE_TIMEOUT_MS);
    endCompression(&codec);
  } else {
    client.print("\r\n");
    relayUntilClosed(client, upstream, CONNECT_IDLE_TIMEOUT_MS);
  }
  upstream.stop();
}

static bool forwardRequestHeaders(WiFiClient &upstream, char *headers,
                                  const char *host, uint16_t port,
                                  const char *path, const char *method,
                                  const char *version, bool websocketUpgrade,
                                  uint32_t *bodyLength) {
  char requestLine[REQUEST_LINE_CAPACITY];
  const int lineLength = snprintf(requestLine, sizeof(requestLine), "%s %s %s\r\n",
                                  method, path, version);
  if (lineLength < 0 || static_cast<size_t>(lineLength) >= sizeof(requestLine) ||
      !writeAll(upstream, reinterpret_cast<uint8_t *>(requestLine), lineLength)) {
    return false;
  }

  bool contentLengthSeen = false;
  char *line = headers;
  while (*line) {
    char *lineEnd = strstr(line, "\r\n");
    if (lineEnd == nullptr) {
      break;
    }
    *lineEnd = '\0';
    char *colon = strchr(line, ':');
    if (colon != nullptr) {
      *colon = '\0';
      char *value = colon + 1;
      while (*value == ' ' || *value == '\t') {
        ++value;
      }
      const bool isContentLength = strcasecmp(line, "Content-Length") == 0;
      if (isContentLength) {
        char *end = nullptr;
        const unsigned long parsed = strtoul(value, &end, 10);
        if (end == value || *end != '\0' || parsed > MAX_REQUEST_BODY_BYTES ||
            (contentLengthSeen && parsed != *bodyLength)) {
          return false;
        }
        *bodyLength = static_cast<uint32_t>(parsed);
        contentLengthSeen = true;
      } else if (strcasecmp(line, "Transfer-Encoding") == 0) {
        return false;
      }

      const bool removeHeader = isContentLength ||
                                strcasecmp(line, "Host") == 0 ||
                                strcasecmp(line, "Connection") == 0 ||
                                strcasecmp(line, "Upgrade") == 0 ||
                                strcasecmp(line, "Proxy-Connection") == 0 ||
                                strcasecmp(line, "Proxy-Authorization") == 0 ||
                                strcasecmp(line, "Keep-Alive") == 0 ||
                                strcasecmp(line, "Expect") == 0;
      *colon = ':';
      if (!removeHeader &&
          (!writeAll(upstream, reinterpret_cast<uint8_t *>(line), strlen(line)) ||
           !writeAll(upstream, reinterpret_cast<const uint8_t *>("\r\n"), 2))) {
        return false;
      }
    }
    line = lineEnd + 2;
  }

  if (*bodyLength > 0) {
    upstream.printf("Content-Length: %lu\r\n",
                    static_cast<unsigned long>(*bodyLength));
  }
  if (port == 80) {
    upstream.printf("Host: %s\r\n", host);
  } else {
    upstream.printf("Host: %s:%u\r\n", host, port);
  }
  if (websocketUpgrade) {
    upstream.print("Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n");
  } else {
    upstream.print("Connection: close\r\n\r\n");
  }
  return true;
}

static void handleHttpRequest(WiFiClient &client, char *requestHeader) {
  char method[16];
  char target[REQUEST_LINE_CAPACITY];
  char version[16];
  char *headers;
  if (!parseRequestLine(requestHeader, method, target, version, &headers)) {
    sendError(client, 400, "Bad Request", "Malformed request line");
    return;
  }

  char *headersEnd = strstr(headers, "\r\n\r\n");
  if (headersEnd == nullptr) {
    sendError(client, 400, "Bad Request", "Malformed request headers");
    return;
  }
  *headersEnd = '\0';

  if (strcmp(method, "CONNECT") == 0) {
    bool compressedTunnel = false;
    if (hasHeader(headers, COMPRESSED_CONNECT_HEADER)) {
      char compressionMode[32];
      if (!getHeaderValue(headers, COMPRESSED_CONNECT_HEADER, compressionMode,
                          sizeof(compressionMode)) ||
          strcmp(compressionMode, COMPRESSED_CONNECT_VALUE) != 0) {
        sendError(client, 400, "Bad Request",
                  "Unsupported CONNECT compression mode");
        return;
      }
      compressedTunnel = true;
    }
    handleConnect(client, target, compressedTunnel);
    return;
  }
  const bool hasUpgradeHeader = hasHeader(headers, "Upgrade");
  const bool websocketUpgrade = isWebSocketUpgrade(headers);
  if (hasUpgradeHeader && !websocketUpgrade) {
    sendError(client, 501, "Not Implemented",
              "Only WebSocket upgrades are supported");
    return;
  }
  if (websocketUpgrade &&
      (strcmp(method, "GET") != 0 || strcmp(version, "HTTP/1.1") != 0)) {
    sendError(client, 400, "Bad Request",
              "WebSocket upgrades require GET with HTTP/1.1");
    return;
  }
  if (hasHeader(headers, "Transfer-Encoding") || hasHeader(headers, "Expect")) {
    sendError(client, 501, "Not Implemented",
              "Chunked request bodies and Expect are not supported");
    return;
  }

  char host[HOST_CAPACITY];
  char path[PATH_CAPACITY];
  uint16_t port;
  if (!parseHttpTarget(target, headers, host, &port, path)) {
    sendError(client, 400, "Bad Request",
              "Only HTTP and WebSocket proxy requests are supported");
    return;
  }

  IPAddress address;
  WiFiClient upstream;
  if (!connectToLocalTarget(host, port, &address, &upstream)) {
    sendError(client, 502, "Bad Gateway",
              "Target is unreachable or outside the local Wi-Fi subnet");
    return;
  }

  uint32_t bodyLength = 0;
  if (!forwardRequestHeaders(upstream, headers, host, port, path, method,
                             version, websocketUpgrade, &bodyLength)) {
    sendError(client, 400, "Bad Request", "Unsupported or invalid request headers");
    upstream.stop();
    return;
  }
  if (websocketUpgrade) {
    if (bodyLength != 0) {
      upstream.stop();
      sendError(client, 400, "Bad Request",
                "WebSocket upgrade requests cannot have a body");
      return;
    }
    relayUntilClosed(client, upstream, WEBSOCKET_IDLE_TIMEOUT_MS);
    upstream.stop();
    return;
  }
  if (bodyLength > 0 && !copyExact(client, upstream, bodyLength)) {
    upstream.stop();
    return;
  }
  relayUntilClosed(client, upstream, UPSTREAM_IDLE_TIMEOUT_MS);
  upstream.stop();
}

static void serviceProxy() {
  if (!proxyStarted) {
    return;
  }
  WiFiClient client = proxyServer.available();
  if (!client) {
    return;
  }

  portENTER_CRITICAL(&proxyClientMux);
  const bool atCapacity = activeProxyClients >= MAX_PROXY_CLIENTS;
  if (!atCapacity) {
    ++activeProxyClients;
  }
  portEXIT_CRITICAL(&proxyClientMux);
  if (atCapacity) {
    sendError(client, 503, "Service Unavailable", "Proxy client limit reached");
    client.stop();
    return;
  }

  ProxyClientTaskContext *context = new (std::nothrow) ProxyClientTaskContext;
  if (context == nullptr) {
    portENTER_CRITICAL(&proxyClientMux);
    --activeProxyClients;
    portEXIT_CRITICAL(&proxyClientMux);
    sendError(client, 503, "Service Unavailable", "Could not allocate proxy task");
    client.stop();
    return;
  }
  context->client = client;
  if (xTaskCreate(proxyClientTask, "proxy-client", PROXY_CLIENT_STACK_SIZE,
                  context, 1, nullptr) != pdPASS) {
    delete context;
    portENTER_CRITICAL(&proxyClientMux);
    --activeProxyClients;
    portEXIT_CRITICAL(&proxyClientMux);
    sendError(client, 503, "Service Unavailable", "Could not start proxy task");
    client.stop();
  }
}

static void proxyClientTask(void *argument) {
  ProxyClientTaskContext *context =
      static_cast<ProxyClientTaskContext *>(argument);
  WiFiClient &client = context->client;
  client.setNoDelay(true);
  client.setTimeout(CLIENT_HEADER_TIMEOUT_MS);
  char requestHeader[REQUEST_HEADER_CAPACITY];
  if (!readHeader(client, requestHeader, sizeof(requestHeader))) {
    sendError(client, 431, "Request Header Fields Too Large",
              "Request header missing, too large, or timed out");
  } else {
    handleHttpRequest(client, requestHeader);
  }
  client.stop();
  delete context;

  portENTER_CRITICAL(&proxyClientMux);
  --activeProxyClients;
  portEXIT_CRITICAL(&proxyClientMux);
  vTaskDelete(nullptr);
}

void setup() {
  Serial.begin(115200);
  delay(200);
  Serial.println();
  Serial.println("ESP32 WireGuard HTTP proxy starting");
  WiFi.mode(WIFI_STA);
  WiFi.setAutoReconnect(true);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  nextWifiAttemptAt = millis() + WIFI_RETRY_INTERVAL_MS;
  scanServer.begin();
  if (xTaskCreate(scanServerTask, "lan-scan", 6144, nullptr, 1, nullptr) != pdPASS) {
    Serial.println("Failed to start LAN scan task.");
  } else {
    Serial.printf("LAN scan endpoint listening on port %u (/scan).\n",
                  HTTP_SCAN_PORT);
  }
}

void loop() {
  maintainNetwork();
  serviceProxy();
  delay(1);
}
