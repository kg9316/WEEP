#include <Arduino.h>
#include <WiFi.h>
#include <WebServer.h>
#include <WebSocketsServer.h>
#include <ESPmDNS.h>
#include <SPIFFS.h>
#include <SD_MMC.h>
#include <ArduinoJson.h>
#include <map>
#include <vector>
#include <mbedtls/md.h>
#include "secrets.h"

static const uint16_t HTTP_PORT = 80;
static const uint16_t WS_PORT = 81;

WebServer httpServer(HTTP_PORT);
WebSocketsServer wsServer(WS_PORT);

static const char* AUTH_MECH = "auth:scram-sha256";
static const char* DEMO_USER = "admin";
static const char* DEMO_PASS = "admin";
static const uint8_t FRAME_FLAG_FINAL = 0x01;
static const uint8_t FRAME_FLAG_ACK = 0x02;
static const size_t FRAME_HEADER_SIZE = 7;
static const size_t SERVER_CHUNK_SIZE = 8192;

struct UploadState
{
  bool active = false;
  String path;
  uint32_t expectedSize = 0;
  uint32_t received = 0;
  uint32_t confirmMsgno = 0;
  uint32_t nextSeq = 0;
  File file;
};

struct ClientState
{
  bool authenticated = false;
  bool awaitingClientProof = false;
  String username;
  String serverNonce;
  String expectedClientProof;
  std::map<uint16_t, String> channels;
  std::map<uint16_t, UploadState> uploads;
};

static std::map<uint8_t, ClientState> gClients;
static bool gFileStorageReady = false;

static String toHex(const uint8_t* data, size_t len)
{
  static const char* hex = "0123456789abcdef";
  String out;
  out.reserve(len * 2);
  for (size_t i = 0; i < len; i++)
  {
    out += hex[(data[i] >> 4) & 0x0F];
    out += hex[data[i] & 0x0F];
  }
  return out;
}

static bool fromHex(const String& hex, std::vector<uint8_t>& out)
{
  if (hex.length() % 2 != 0)
  {
    return false;
  }

  out.clear();
  out.reserve(hex.length() / 2);
  for (size_t i = 0; i < hex.length(); i += 2)
  {
    char hi = hex.charAt(i);
    char lo = hex.charAt(i + 1);
    uint8_t h = (hi >= '0' && hi <= '9') ? (hi - '0')
              : (hi >= 'a' && hi <= 'f') ? (hi - 'a' + 10)
              : (hi >= 'A' && hi <= 'F') ? (hi - 'A' + 10)
              : 255;
    uint8_t l = (lo >= '0' && lo <= '9') ? (lo - '0')
              : (lo >= 'a' && lo <= 'f') ? (lo - 'a' + 10)
              : (lo >= 'A' && lo <= 'F') ? (lo - 'A' + 10)
              : 255;
    if (h == 255 || l == 255)
    {
      out.clear();
      return false;
    }
    out.push_back((h << 4) | l);
  }

  return true;
}

static String randomHex(size_t bytes)
{
  std::vector<uint8_t> raw(bytes);
  for (size_t i = 0; i < bytes; i += 4)
  {
    uint32_t r = esp_random();
    for (size_t j = 0; j < 4 && (i + j) < bytes; j++)
    {
      raw[i + j] = (r >> (j * 8)) & 0xFF;
    }
  }
  return toHex(raw.data(), raw.size());
}

static bool hmacSha256(const std::vector<uint8_t>& key, const String& input, std::vector<uint8_t>& out)
{
  out.assign(32, 0);
  const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if (md == nullptr)
  {
    return false;
  }

  int rc = mbedtls_md_hmac(
    md,
    key.data(),
    key.size(),
    reinterpret_cast<const unsigned char*>(input.c_str()),
    input.length(),
    out.data());
  return rc == 0;
}

static bool pbkdf2Sha256(const String& password, const String& saltHex, uint32_t iterations, std::vector<uint8_t>& out)
{
  std::vector<uint8_t> salt;
  if (!fromHex(saltHex, salt))
  {
    return false;
  }

  if (iterations == 0)
  {
    return false;
  }

  out.assign(32, 0);
  const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if (md == nullptr)
  {
    return false;
  }

  std::vector<uint8_t> block;
  block.reserve(salt.size() + 4);
  block.insert(block.end(), salt.begin(), salt.end());
  // PBKDF2 block index is 1-based, big-endian.
  block.push_back(0x00);
  block.push_back(0x00);
  block.push_back(0x00);
  block.push_back(0x01);

  std::vector<uint8_t> u(32, 0);
  std::vector<uint8_t> t(32, 0);

  int rc = mbedtls_md_hmac(
    md,
    reinterpret_cast<const unsigned char*>(password.c_str()),
    password.length(),
    block.data(),
    block.size(),
    u.data());
  if (rc != 0)
  {
    return false;
  }

  for (size_t i = 0; i < t.size(); i++)
  {
    t[i] = u[i];
  }

  for (uint32_t i = 1; i < iterations; i++)
  {
    rc = mbedtls_md_hmac(
      md,
      reinterpret_cast<const unsigned char*>(password.c_str()),
      password.length(),
      u.data(),
      u.size(),
      u.data());
    if (rc != 0)
    {
      return false;
    }

    for (size_t j = 0; j < t.size(); j++)
    {
      t[j] ^= u[j];
    }
  }

  out = t;
  return true;
}

static void sendJson(uint8_t clientNum, const JsonDocument& doc)
{
  String text;
  serializeJson(doc, text);
  wsServer.sendTXT(clientNum, text);
}

static void sendError(uint8_t clientNum, uint16_t channel, uint32_t msgno, int code, const String& message)
{
  StaticJsonDocument<256> doc;
  doc["type"] = "ERR";
  doc["channel"] = channel;
  doc["msgno"] = msgno;
  JsonObject payload = doc.createNestedObject("payload");
  payload["code"] = code;
  payload["message"] = message;
  sendJson(clientNum, doc);
}

static void sendOk(uint8_t clientNum, uint32_t msgno)
{
  StaticJsonDocument<128> doc;
  doc["type"] = "ok";
  doc["channel"] = 0;
  doc["msgno"] = msgno;
  doc.createNestedObject("payload");
  sendJson(clientNum, doc);
}

static void sendGreeting(uint8_t clientNum)
{
  ClientState& st = gClients[clientNum];

  StaticJsonDocument<512> doc;
  doc["type"] = "greeting";
  doc["channel"] = 0;
  doc["msgno"] = 0;
  JsonObject payload = doc.createNestedObject("payload");

  JsonArray profiles = payload.createNestedArray("profiles");
  profiles.add("weep:file");
  profiles.add("weep:query");

  JsonArray auth = payload.createNestedArray("auth");
  auth.add(AUTH_MECH);

  payload["version"] = "1.2";
  payload["productName"] = "weep-esp32";
  payload["maxChunkSize"] = 8192;
  payload["serverNonce"] = st.serverNonce;

  JsonObject info = payload.createNestedObject("serverInfo");
  info["brand"] = "Olimex";
  info["model"] = "ESP32-POE";
  info["firmware"] = "0.1.0";

  sendJson(clientNum, doc);
}

static void sendAuthRpyStep1(uint8_t clientNum, uint32_t msgno, const String& combinedNonce,
                             const String& serverProof, const String& salt, uint32_t iterations)
{
  StaticJsonDocument<384> doc;
  doc["type"] = "RPY";
  doc["channel"] = 0;
  doc["msgno"] = msgno;
  JsonObject payload = doc.createNestedObject("payload");
  payload["combinedNonce"] = combinedNonce;
  payload["serverProof"] = serverProof;
  payload["salt"] = salt;
  payload["iterations"] = iterations;
  sendJson(clientNum, doc);
}

static void sendAuthRpyStep2(uint8_t clientNum, uint32_t msgno, const String& username)
{
  StaticJsonDocument<256> doc;
  doc["type"] = "RPY";
  doc["channel"] = 0;
  doc["msgno"] = msgno;
  JsonObject payload = doc.createNestedObject("payload");
  payload["ok"] = true;
  payload["username"] = username;
  JsonArray roles = payload.createNestedArray("roles");
  roles.add("admin");
  roles.add("read");
  roles.add("write");
  sendJson(clientNum, doc);
}

static String normalizePath(const String& in)
{
  if (in.length() == 0)
  {
    return String();
  }
  if (in.startsWith("/"))
  {
    return in;
  }
  return String("/") + in;
}

static void sendRpy(uint8_t clientNum, uint16_t channel, uint32_t msgno, const JsonObjectConst& payload)
{
  DynamicJsonDocument doc(1024);
  doc["type"] = "RPY";
  doc["channel"] = channel;
  doc["msgno"] = msgno;
  JsonObject out = doc.createNestedObject("payload");
  for (JsonPairConst kv : payload)
  {
    out[kv.key()] = kv.value();
  }
  sendJson(clientNum, doc);
}

static void sendAckFrame(uint8_t clientNum, uint16_t channel, uint32_t seq)
{
  uint8_t ack[FRAME_HEADER_SIZE];
  ack[0] = (channel >> 8) & 0xFF;
  ack[1] = channel & 0xFF;
  ack[2] = (seq >> 24) & 0xFF;
  ack[3] = (seq >> 16) & 0xFF;
  ack[4] = (seq >> 8) & 0xFF;
  ack[5] = seq & 0xFF;
  ack[6] = FRAME_FLAG_ACK;
  wsServer.sendBIN(clientNum, ack, FRAME_HEADER_SIZE);
}

static void sendDataFrame(uint8_t clientNum, uint16_t channel, uint32_t seq,
                          const uint8_t* data, size_t len, bool isFinal)
{
  std::vector<uint8_t> frame(FRAME_HEADER_SIZE + len);
  frame[0] = (channel >> 8) & 0xFF;
  frame[1] = channel & 0xFF;
  frame[2] = (seq >> 24) & 0xFF;
  frame[3] = (seq >> 16) & 0xFF;
  frame[4] = (seq >> 8) & 0xFF;
  frame[5] = seq & 0xFF;
  frame[6] = isFinal ? FRAME_FLAG_FINAL : 0;
  if (len > 0)
  {
    memcpy(frame.data() + FRAME_HEADER_SIZE, data, len);
  }
  wsServer.sendBIN(clientNum, frame.data(), frame.size());
}

static void handleUploadBinary(uint8_t clientNum, uint16_t channel, uint32_t seq, bool isFinal,
                               const uint8_t* data, size_t len)
{
  auto clientIt = gClients.find(clientNum);
  if (clientIt == gClients.end())
  {
    return;
  }

  ClientState& st = clientIt->second;
  auto upIt = st.uploads.find(channel);
  if (upIt == st.uploads.end() || !upIt->second.active)
  {
    return;
  }

  UploadState& up = upIt->second;
  if (seq != up.nextSeq)
  {
    Serial.printf("[ws] ch=%u upload seq mismatch got=%u expected=%u\n", channel, seq, up.nextSeq);
    sendError(clientNum, channel, up.confirmMsgno, 400, "Out-of-order upload frame");
    if (up.file)
    {
      up.file.close();
    }
    st.uploads.erase(upIt);
    return;
  }

  if (len > 0)
  {
    size_t written = up.file.write(data, len);
    if (written != len)
    {
      Serial.printf("[ws] ch=%u upload write failed wrote=%u len=%u\n", channel, static_cast<unsigned>(written), static_cast<unsigned>(len));
      sendError(clientNum, channel, up.confirmMsgno, 500, "MMC write failed");
      if (up.file)
      {
        up.file.close();
      }
      st.uploads.erase(upIt);
      return;
    }
    up.received += static_cast<uint32_t>(len);
  }

  sendAckFrame(clientNum, channel, seq);
  up.nextSeq++;

  if ((up.nextSeq % 64) == 0)
  {
    Serial.printf("[ws] ch=%u upload progress seq=%u received=%u/%u\n",
                  channel,
                  up.nextSeq,
                  up.received,
                  up.expectedSize);
  }

  if (isFinal || up.received >= up.expectedSize)
  {
    if (up.file)
    {
      up.file.close();
    }

    StaticJsonDocument<256> body;
    body["ok"] = true;
    body["path"] = up.path;
    body["size"] = up.received;
    sendRpy(clientNum, channel, up.confirmMsgno, body.as<JsonObjectConst>());
    Serial.printf("[ws] ch=%u upload complete path=%s size=%u\n", channel, up.path.c_str(), up.received);
    st.uploads.erase(upIt);
  }
}

static String guessMime(const String& path)
{
  if (path.endsWith(".html")) return "text/html";
  if (path.endsWith(".txt")) return "text/plain";
  if (path.endsWith(".json")) return "application/json";
  if (path.endsWith(".csv")) return "text/csv";
  if (path.endsWith(".jpg") || path.endsWith(".jpeg")) return "image/jpeg";
  if (path.endsWith(".png")) return "image/png";
  return "application/octet-stream";
}

static bool ensureFileStorage(uint8_t clientNum, uint16_t channel, uint32_t msgno)
{
  if (gFileStorageReady)
  {
    return true;
  }
  sendError(clientNum, channel, msgno, 503, "MMC storage not mounted");
  return false;
}

static bool deletePathRecursive(const String& path)
{
  if (path.length() == 0 || path == "/")
  {
    return false;
  }

  File node = SD_MMC.open(path);
  if (!node)
  {
    return false;
  }

  if (!node.isDirectory())
  {
    node.close();
    return SD_MMC.remove(path);
  }

  File child = node.openNextFile();
  while (child)
  {
    String childPath = String(child.name());
    child.close();

    if (!deletePathRecursive(childPath))
    {
      node.close();
      return false;
    }

    child = node.openNextFile();
  }

  node.close();
  return SD_MMC.rmdir(path);
}

static void handleChannelMsg(uint8_t clientNum, uint16_t channel, uint32_t msgno, const JsonObjectConst& payload)
{
  ClientState& st = gClients[clientNum];
  if (!st.authenticated)
  {
    sendError(clientNum, channel, msgno, 401, "Not authenticated");
    return;
  }

  auto it = st.channels.find(channel);
  if (it == st.channels.end())
  {
    sendError(clientNum, channel, msgno, 404, "Channel not open");
    return;
  }

  const String profile = it->second;
  const String op = payload["op"] | "";

  if (profile == "weep:file")
  {
    if (!ensureFileStorage(clientNum, channel, msgno))
    {
      return;
    }

    if (op == "list")
    {
      const String path = payload["path"] | "/";
      Serial.printf("[ws] ch=%u op=list path=%s\n", channel, path.c_str());

      DynamicJsonDocument doc(4096);
      doc["type"] = "RPY";
      doc["channel"] = channel;
      doc["msgno"] = msgno;
      JsonObject body = doc.createNestedObject("payload");
      body["path"] = path;
      JsonArray entries = body.createNestedArray("entries");

      File root = SD_MMC.open("/");
      if (!root || !root.isDirectory())
      {
        sendError(clientNum, channel, msgno, 500, "Failed to enumerate MMC root");
        return;
      }

      File file = root.openNextFile();
      while (file)
      {
        String name = String(file.name());
        if (path != "/")
        {
          if (!name.startsWith(path))
          {
            file = root.openNextFile();
            continue;
          }
        }

        JsonObject e = entries.createNestedObject();
        String normName = normalizePath(name);
        e["name"] = normName.startsWith("/") ? normName.substring(1) : normName;
        e["path"] = normName;
        e["type"] = file.isDirectory() ? "dir" : "file";
        e["size"] = file.isDirectory() ? 0 : static_cast<uint32_t>(file.size());
        e["mime"] = file.isDirectory() ? "" : guessMime(name);
        file = root.openNextFile();
      }
      root.close();

      sendJson(clientNum, doc);
      return;
    }

    if (op == "stat")
    {
      const String path = normalizePath(payload["path"] | "");
      Serial.printf("[ws] ch=%u op=stat path=%s\n", channel, path.c_str());
      if (path.length() == 0 || !SD_MMC.exists(path))
      {
        sendError(clientNum, channel, msgno, 404, "Path not found");
        return;
      }

      File f = SD_MMC.open(path, FILE_READ);
      DynamicJsonDocument doc(512);
      doc["type"] = "RPY";
      doc["channel"] = channel;
      doc["msgno"] = msgno;
      JsonObject body = doc.createNestedObject("payload");
      body["path"] = path;
      body["name"] = path.startsWith("/") ? path.substring(1) : path;
      body["type"] = f.isDirectory() ? "dir" : "file";
      body["size"] = f.isDirectory() ? 0 : static_cast<uint32_t>(f.size());
      body["mime"] = f.isDirectory() ? "" : guessMime(path);
      sendJson(clientNum, doc);
      f.close();
      return;
    }

    if (op == "upload")
    {
      String path = normalizePath(payload["path"] | "");
      uint32_t size = payload["size"] | 0;
      if (path.length() == 0)
      {
        sendError(clientNum, channel, msgno, 400, "upload path required");
        return;
      }

      auto existing = st.uploads.find(channel);
      if (existing != st.uploads.end() && existing->second.active)
      {
        sendError(clientNum, channel, msgno, 409, "Upload already in progress on channel");
        return;
      }

      // Start from a clean file each upload.
      if (SD_MMC.exists(path))
      {
        SD_MMC.remove(path);
      }

      UploadState& up = st.uploads[channel];
      up = UploadState{};
      up.file = SD_MMC.open(path, FILE_WRITE);
      if (!up.file)
      {
        st.uploads.erase(channel);
        sendError(clientNum, channel, msgno, 500, "Failed to open MMC file for upload");
        return;
      }

      up.active = true;
      up.path = path;
      up.expectedSize = size;
      up.received = 0;
      up.confirmMsgno = msgno;
      up.nextSeq = 0;

      StaticJsonDocument<128> body;
      body["chunkSize"] = SERVER_CHUNK_SIZE;
      sendRpy(clientNum, channel, msgno, body.as<JsonObjectConst>());
      Serial.printf("[ws] ch=%u upload start path=%s expected=%u\n", channel, path.c_str(), size);
      return;
    }

    if (op == "download")
    {
      String path = normalizePath(payload["path"] | "");
      if (path.length() == 0 || !SD_MMC.exists(path))
      {
        sendError(clientNum, channel, msgno, 404, "Path not found");
        return;
      }

      File f = SD_MMC.open(path, FILE_READ);
      if (!f)
      {
        sendError(clientNum, channel, msgno, 500, "Failed to open MMC file for download");
        return;
      }

      uint32_t total = static_cast<uint32_t>(f.size());
      StaticJsonDocument<256> body;
      body["path"] = path;
      body["size"] = total;
      body["mime"] = guessMime(path);
      sendRpy(clientNum, channel, msgno, body.as<JsonObjectConst>());

      std::vector<uint8_t> chunk(SERVER_CHUNK_SIZE);
      uint32_t seq = 0;
      while (true)
      {
        size_t n = f.read(chunk.data(), chunk.size());
        bool final = (n == 0) || !f.available();
        if (n > 0)
        {
          sendDataFrame(clientNum, channel, seq, chunk.data(), n, final);
          seq++;
        }
        if (final)
        {
          break;
        }
        delay(0);
      }
      f.close();
      Serial.printf("[ws] ch=%u download complete path=%s bytes=%u\n", channel, path.c_str(), total);
      return;
    }

    if (op == "delete")
    {
      String path = normalizePath(payload["path"] | "");
      if (path.length() == 0 || path == "/")
      {
        sendError(clientNum, channel, msgno, 400, "delete path required");
        return;
      }

      if (!SD_MMC.exists(path))
      {
        sendError(clientNum, channel, msgno, 404, "Path not found");
        return;
      }

      if (!deletePathRecursive(path))
      {
        sendError(clientNum, channel, msgno, 500, "Failed to delete path");
        return;
      }

      StaticJsonDocument<128> body;
      body["ok"] = true;
      body["path"] = path;
      sendRpy(clientNum, channel, msgno, body.as<JsonObjectConst>());
      Serial.printf("[ws] ch=%u delete path=%s\n", channel, path.c_str());
      return;
    }

    sendError(clientNum, channel, msgno, 501, "weep:file op not implemented");
    return;
  }

  if (profile == "weep:query")
  {
    if (op != "query")
    {
      sendError(clientNum, channel, msgno, 400, "query op required");
      return;
    }

    DynamicJsonDocument doc(768);
    doc["type"] = "RPY";
    doc["channel"] = channel;
    doc["msgno"] = msgno;
    JsonObject body = doc.createNestedObject("payload");
    String q = payload["q"] | "";
    Serial.printf("[ws] ch=%u op=query q=%s\n", channel, q.c_str());
    body["resultType"] = "array";
    body["query"] = q;
    JsonArray items = body.createNestedArray("items");
    JsonObject r1 = items.createNestedObject();
    r1["name"] = "row1";
    r1["value"] = 123;
    JsonObject r2 = items.createNestedObject();
    r2["name"] = "row2";
    r2["value"] = 456;
    sendJson(clientNum, doc);
    return;
  }

  sendError(clientNum, channel, msgno, 501, "Unsupported profile");
}

static void handleManagement(uint8_t clientNum, const String& type, uint32_t msgno, const JsonObjectConst& payload)
{
  ClientState& st = gClients[clientNum];

  if (type == "hello")
  {
    (void)msgno;
    (void)payload;
    Serial.printf("[ws] client %u requested greeting\n", clientNum);
    sendGreeting(clientNum);
    return;
  }

  if (type == "MSG" && payload.containsKey("mechanism"))
  {
    const String mechanism = payload["mechanism"] | "";
    if (mechanism != AUTH_MECH)
    {
      sendError(clientNum, 0, msgno, 400, "Only auth:scram-sha256 is supported");
      return;
    }

    const String username = payload["username"] | "";
    if (username.length() == 0)
    {
      sendError(clientNum, 0, msgno, 400, "username required");
      return;
    }

    if (payload.containsKey("clientNonce"))
    {
      const String clientNonce = payload["clientNonce"] | "";
      if (clientNonce.length() < 16)
      {
        sendError(clientNum, 0, msgno, 400, "clientNonce too short");
        return;
      }

      const String salt = randomHex(16);
      const uint32_t iterations = 10000;
      const String combinedNonce = clientNonce + st.serverNonce;

      std::vector<uint8_t> passwordKey;
      std::vector<uint8_t> sharedKey;
      std::vector<uint8_t> serverProof;
      std::vector<uint8_t> clientProof;

      if (!pbkdf2Sha256(DEMO_PASS, salt, iterations, passwordKey) ||
          !hmacSha256(passwordKey, combinedNonce, sharedKey) ||
          !hmacSha256(sharedKey, String("server:") + combinedNonce, serverProof) ||
          !hmacSha256(sharedKey, String("client:") + combinedNonce, clientProof))
      {
        sendError(clientNum, 0, msgno, 500, "SCRAM calculation failed");
        return;
      }

      st.username = username;
      st.awaitingClientProof = true;
      st.expectedClientProof = toHex(clientProof.data(), clientProof.size());

      sendAuthRpyStep1(
        clientNum,
        msgno,
        combinedNonce,
        toHex(serverProof.data(), serverProof.size()),
        salt,
        iterations);
      return;
    }

    if (payload.containsKey("clientProof"))
    {
      if (!st.awaitingClientProof)
      {
        sendError(clientNum, 0, msgno, 400, "No SCRAM challenge in progress");
        return;
      }

      const String clientProofHex = payload["clientProof"] | "";
      if (clientProofHex != st.expectedClientProof)
      {
        sendError(clientNum, 0, msgno, 401, "Invalid credentials");
        return;
      }

      st.awaitingClientProof = false;
      st.authenticated = true;
      if (st.username.length() == 0)
      {
        st.username = DEMO_USER;
      }
      sendAuthRpyStep2(clientNum, msgno, st.username);
      return;
    }

    sendError(clientNum, 0, msgno, 400, "SCRAM payload missing nonce/proof");
    return;
  }

  if (type == "clientInfo")
  {
    sendOk(clientNum, msgno);
    return;
  }

  if (type == "start")
  {
    if (!st.authenticated)
    {
      sendError(clientNum, 0, msgno, 401, "Authenticate before opening channels");
      return;
    }

    uint16_t channel = payload["channel"] | 0;
    String profile = payload["profile"] | "";
    if (channel == 0 || profile.length() == 0)
    {
      sendError(clientNum, 0, msgno, 400, "channel and profile required");
      return;
    }

    if (profile != "weep:file" && profile != "weep:query")
    {
      sendError(clientNum, 0, msgno, 501, "Profile not supported");
      return;
    }

    if (st.channels.find(channel) != st.channels.end())
    {
      sendError(clientNum, 0, msgno, 409, "Channel already open");
      return;
    }

    st.channels[channel] = profile;
    sendOk(clientNum, msgno);
    return;
  }

  if (type == "close")
  {
    uint16_t channel = payload["channel"] | 0;
    if (channel != 0)
    {
      auto upIt = st.uploads.find(channel);
      if (upIt != st.uploads.end())
      {
        if (upIt->second.file)
        {
          upIt->second.file.close();
        }
        st.uploads.erase(upIt);
      }
      st.channels.erase(channel);
    }
    sendOk(clientNum, msgno);
    return;
  }

  sendError(clientNum, 0, msgno, 400, String("Unknown management message: ") + type);
}

static String deviceName()
{
  String mac = WiFi.macAddress();
  mac.replace(":", "");
  return String("esp32-poe-") + mac.substring(mac.length() - 6);
}

static String wsUrl()
{
  IPAddress ip = WiFi.localIP();
  return String("ws://") + ip.toString() + ":" + WS_PORT;
}

static bool isSameSubnet(const IPAddress& a, const IPAddress& b, const IPAddress& mask)
{
  for (int i = 0; i < 4; ++i)
  {
    if ((a[i] & mask[i]) != (b[i] & mask[i]))
    {
      return false;
    }
  }
  return true;
}

static String httpContentType(const String& path)
{
  if (path.endsWith(".html")) return "text/html; charset=utf-8";
  if (path.endsWith(".js")) return "application/javascript; charset=utf-8";
  if (path.endsWith(".css")) return "text/css; charset=utf-8";
  if (path.endsWith(".json")) return "application/json; charset=utf-8";
  if (path.endsWith(".svg")) return "image/svg+xml";
  if (path.endsWith(".png")) return "image/png";
  if (path.endsWith(".jpg") || path.endsWith(".jpeg")) return "image/jpeg";
  if (path.endsWith(".ico")) return "image/x-icon";
  return "application/octet-stream";
}

static void handleSpiffsAsset()
{
  const String path = httpServer.uri();
  File f = SPIFFS.open(path, "r");
  if (!f || f.size() == 0)
  {
    httpServer.send(404, "text/plain", "Asset not found");
    return;
  }

  httpServer.streamFile(f, httpContentType(path));
  f.close();
}

static void handleWeepUi()
{
  File f = SPIFFS.open("/index.html", "r");
  if (!f || f.size() == 0)
  {
    httpServer.send(
      500,
      "text/html; charset=utf-8",
      "<!doctype html><html><body style='font-family:Arial,sans-serif;padding:1rem'>"
      "<h2>WEEP UI missing from SPIFFS</h2>"
      "<p>Upload filesystem image with <code>pio run -t uploadfs</code> and reload <code>/weep</code>.</p>"
      "</body></html>");
    return;
  }

  httpServer.streamFile(f, "text/html; charset=utf-8");
  f.close();
}

static void handleDiscover()
{
  DynamicJsonDocument doc(4096);
  JsonArray arr = doc.to<JsonArray>();
  IPAddress localIp = WiFi.localIP();
  IPAddress subnetMask = WiFi.subnetMask();
  String selfName = deviceName();
  String selfHostLocal = selfName + ".local";
  bool selfPresent = false;
  int count = MDNS.queryService("weep", "tcp");
  for (int i = 0; i < count; i++)
  {
    uint16_t port = MDNS.port(i);
    String host = MDNS.hostname(i);
    if (host.length() == 0)
    {
      continue;
    }

    // Use the mDNS-provided endpoint IP from queryService results to avoid DNS resolution failures.
    IPAddress ip = MDNS.address(i);
    bool hasIp = static_cast<uint32_t>(ip) != 0;
    if (hasIp && static_cast<uint32_t>(localIp) != 0 && static_cast<uint32_t>(subnetMask) != 0)
    {
      if (!isSameSubnet(ip, localIp, subnetMask))
      {
        // Skip service addresses outside our local subnet to avoid unreachable targets.
        continue;
      }
    }

    String hostLocal = host;
    if (hostLocal.indexOf('.') < 0)
    {
      hostLocal += ".local";
    }

    JsonObject svc = arr.createNestedObject();
    svc["instanceName"] = host;
    svc["hostName"] = hostLocal;
    svc["port"] = port;
    svc["path"] = (port == WS_PORT) ? "/" : "/weep";
    svc["version"] = "1.2";

    JsonArray auth = svc.createNestedArray("authMechanisms");
    auth.add(AUTH_MECH);

    JsonArray addrs = svc.createNestedArray("addresses");
    if (hasIp)
    {
      addrs.add(ip.toString());
    }
    addrs.add(hostLocal);
    if (!hasIp)
    {
      addrs.add(host);
    }

    String wsHost = hasIp ? ip.toString() : hostLocal;
    svc["wsUrl"] = String("ws://") + wsHost + ":" + String(port);

    bool samePort = port == WS_PORT;
    bool sameIp = hasIp && ip == localIp;
    bool sameHost = host.equalsIgnoreCase(selfName) || hostLocal.equalsIgnoreCase(selfHostLocal);
    if (samePort && (sameIp || sameHost))
    {
      selfPresent = true;
    }
  }

  if (!selfPresent)
  {
    // Ensure self-discovery is always present even when mDNS browse omits our own service.
    JsonObject svc = arr.createNestedObject();
    svc["instanceName"] = selfName;
    svc["hostName"] = selfHostLocal;
    svc["port"] = WS_PORT;
    svc["path"] = "/";
    svc["version"] = "1.2";

    JsonArray auth = svc.createNestedArray("authMechanisms");
    auth.add(AUTH_MECH);

    JsonArray addrs = svc.createNestedArray("addresses");
    addrs.add(localIp.toString());
    addrs.add(selfHostLocal);

    svc["wsUrl"] = wsUrl();
  }

  String payload;
  serializeJson(doc, payload);
  httpServer.sendHeader("Cache-Control", "no-cache");
  httpServer.send(200, "application/json; charset=utf-8", payload);
}

static void onWsEvent(uint8_t clientNum, WStype_t type, uint8_t* payload, size_t length)
{
  switch (type)
  {
    case WStype_CONNECTED:
      gClients[clientNum] = ClientState{};
      gClients[clientNum].serverNonce = randomHex(16);
      Serial.printf("[ws] client %u connected, sending greeting\n", clientNum);
      sendGreeting(clientNum);
      break;

    case WStype_DISCONNECTED:
    {
      auto stIt = gClients.find(clientNum);
      if (stIt != gClients.end())
      {
        for (auto& kv : stIt->second.uploads)
        {
          if (kv.second.file)
          {
            kv.second.file.close();
          }
        }
      }
      gClients.erase(clientNum);
      Serial.printf("[ws] client %u disconnected\n", clientNum);
      break;
    }

    case WStype_TEXT:
    {
      if (length == 0 || payload == nullptr)
      {
        Serial.printf("[ws] client %u sent empty text frame\n", clientNum);
        break;
      }

      DynamicJsonDocument doc(2048);
      DeserializationError err = deserializeJson(doc, payload, length);
      if (err)
      {
        Serial.printf("[ws] client %u invalid json: %s\n", clientNum, err.c_str());
        break;
      }

      String msgType = doc["type"] | "";
      uint16_t channel = doc["channel"] | 0;
      uint32_t msgno = doc["msgno"] | 0;
      JsonObjectConst body = doc["payload"].as<JsonObjectConst>();

      if (msgType.length() == 0)
      {
        sendError(clientNum, channel, msgno, 400, "type required");
        break;
      }

      if (channel == 0)
      {
        handleManagement(clientNum, msgType, msgno, body);
      }
      else if (msgType == "MSG")
      {
        handleChannelMsg(clientNum, channel, msgno, body);
      }
      else
      {
        sendError(clientNum, channel, msgno, 400, "Unsupported message type for channel");
      }
      break;
    }

    case WStype_BIN:
    {
      if (length < FRAME_HEADER_SIZE || payload == nullptr)
      {
        break;
      }

      uint16_t channel = (static_cast<uint16_t>(payload[0]) << 8) | payload[1];
      uint32_t seq =
        (static_cast<uint32_t>(payload[2]) << 24) |
        (static_cast<uint32_t>(payload[3]) << 16) |
        (static_cast<uint32_t>(payload[4]) << 8) |
        static_cast<uint32_t>(payload[5]);
      uint8_t flags = payload[6];
      bool isAck = (flags & FRAME_FLAG_ACK) != 0 && length == FRAME_HEADER_SIZE;
      bool isFinal = (flags & FRAME_FLAG_FINAL) != 0;

      if (isAck)
      {
        // Download ACKs are currently not flow-controlled on server side.
        break;
      }

      handleUploadBinary(
        clientNum,
        channel,
        seq,
        isFinal,
        payload + FRAME_HEADER_SIZE,
        length - FRAME_HEADER_SIZE);
      break;
    }

    default:
      break;
  }
}

static void connectWifi()
{
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS);

  Serial.print("[wifi] connecting");
  uint32_t start = millis();
  while (WiFi.status() != WL_CONNECTED)
  {
    delay(400);
    Serial.print('.');
    if (millis() - start > 30000)
    {
      Serial.println("\n[wifi] timeout, restarting");
      ESP.restart();
    }
  }

  Serial.println();
  Serial.printf("[wifi] connected, ip=%s\n", WiFi.localIP().toString().c_str());
}

static void initFileStorage()
{
  gFileStorageReady = SD_MMC.begin("/sdcard", true);
  if (!gFileStorageReady)
  {
    Serial.println("[mmc] mount failed (SD_MMC)");
    return;
  }

  if (SD_MMC.cardType() == CARD_NONE)
  {
    Serial.println("[mmc] no card present");
    gFileStorageReady = false;
    return;
  }

  Serial.printf("[mmc] mounted total=%llu used=%llu\n", SD_MMC.totalBytes(), SD_MMC.usedBytes());
}

static void initMdns()
{
  String name = deviceName();
  if (!MDNS.begin(name.c_str()))
  {
    Serial.println("[mdns] start failed");
    return;
  }

  MDNS.addService("weep", "tcp", WS_PORT);
  MDNS.addServiceTxt("weep", "tcp", "path", "/");
  MDNS.addServiceTxt("weep", "tcp", "version", "1.2");
  MDNS.addServiceTxt("weep", "tcp", "auth", AUTH_MECH);
  Serial.printf("[mdns] advertised: %s._weep._tcp.local:%u\n", name.c_str(), WS_PORT);
}

void setup()
{
  Serial.begin(115200);
  delay(300);

  if (!SPIFFS.begin(true))
  {
    Serial.println("[spiffs] mount failed");
  }
  else
  {
    Serial.println("[spiffs] mounted");
  }

  initFileStorage();

  connectWifi();
  initMdns();

  httpServer.on("/", HTTP_GET, []() {
    httpServer.sendHeader("Location", "/weep");
    httpServer.send(302, "text/plain", "Redirecting to /weep");
  });
  httpServer.on("/weep", HTTP_GET, handleWeepUi);
  httpServer.on("/weep/", HTTP_GET, handleWeepUi);
  httpServer.on("/weep/discover", HTTP_GET, handleDiscover);
  httpServer.on("/vendor/crypto-js.min.js", HTTP_GET, handleSpiffsAsset);
  httpServer.begin();

  wsServer.begin();
  wsServer.onEvent(onWsEvent);

  Serial.printf("[http] ui: http://%s/weep\n", WiFi.localIP().toString().c_str());
  Serial.printf("[http] discover: http://%s/weep/discover\n", WiFi.localIP().toString().c_str());
  Serial.printf("[ws] endpoint: ws://%s:%u\n", WiFi.localIP().toString().c_str(), WS_PORT);
}

void loop()
{
  httpServer.handleClient();
  wsServer.loop();
}
