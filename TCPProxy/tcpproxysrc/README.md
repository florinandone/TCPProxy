# tcpproxy

A small, dependency-free **TCP proxy** written for **Java 8** using non-blocking
NIO best practices, with an optional **Wireshark-readable journal** and a
**replay server** that can answer clients from a previously captured journal.

## Features

- **`TcpProxy`** — single-threaded, non-blocking NIO proxy. Listens on a host/port
  and forwards every connection to a remote host/port in both directions.
  - Zero garbage on the data path: each connection owns two reused direct
    `ByteBuffer`s; reads go straight from one socket into the buffer destined for
    the peer socket — no per-read allocation, no intermediate copy.
  - Proper flow control via `OP_READ`/`OP_WRITE` interest toggling, so a slow
    consumer throttles a fast producer instead of buffering unbounded data.
  - Partial writes retained and retried; TCP half-close honoured.
- **`PcapJournal`** — optional traffic journal written in classic **libpcap**
  format. Each proxied connection becomes one synthetic TCP stream with a
  fabricated SYN/SYN-ACK/ACK handshake, correct IPv4 + TCP **checksums**, and
  monotonic sequence numbers. The `.pcap` opens directly in **Wireshark** and
  supports *Follow TCP Stream*. Writing is allocation-free (one reused scratch
  buffer).
- **`ReplayServer`** — reads a captured journal, extracts what the upstream
  server sent, and replays those responses to connecting clients — no real
  upstream required.

## Usage

```java
// Proxy 127.0.0.1:8080 -> example.com:80, journaling to capture.pcap
PcapJournal journal = new PcapJournal(Paths.get("capture.pcap"));
TcpProxy proxy = new TcpProxy(
        new InetSocketAddress("127.0.0.1", 8080),
        new InetSocketAddress("example.com", 80),
        journal,
        16 * 1024);
proxy.bind();
new Thread(proxy).start();
// ... later
proxy.close();
journal.close();
```

```java
// Replay the captured upstream responses on port 9090
ReplayServer replay = new ReplayServer(
        new InetSocketAddress("127.0.0.1", 9090),
        Paths.get("capture.pcap"));
replay.bind();
new Thread(replay).start();
```

Open `capture.pcap` in Wireshark to dissect the proxied traffic. The two
synthetic endpoints are `10.0.0.1` (client) and `10.0.0.2` (upstream server);
real port numbers are preserved so distinct connections stay in distinct
streams.

## Build & test

```bash
./gradlew test
```

The integration tests (`TcpProxyIntegrationTest`) spin up a server that emits the
current time, confirm it is reachable through the proxy, check the journal is a
valid pcap, then start the `ReplayServer` and confirm it reproduces exactly the
bytes the upstream server originally sent. A second test drives a request/response
echo server and confirms the replay withholds each response until its matching
request arrives.

Compiles to Java 8 bytecode (`options.release = 8`); no runtime dependencies.
