package io.github.florinandone.tcpproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

/**
 * End-to-end test:
 * <ol>
 *   <li>spin up a tiny upstream server that emits the current time and closes;</li>
 *   <li>reach it through the {@link TcpProxy} and confirm the bytes arrive;</li>
 *   <li>confirm the journal is a Wireshark-readable pcap;</li>
 *   <li>start a {@link ReplayServer} from that journal and confirm it reproduces
 *       exactly the bytes the upstream server originally sent.</li>
 * </ol>
 */
class TcpProxyIntegrationTest {

    private final ExecutorService threadPool = Executors.newCachedThreadPool();

    @TempDir
    Path tempDirectory;

    private TimeServer timeServer;
    private TcpProxy proxy;
    private ReplayServer replayServer;

    @BeforeEach
    void setUp() throws IOException {
        timeServer = new TimeServer();
        timeServer.bind();
        threadPool.submit(timeServer);
    }

    @AfterEach
    void tearDown() throws InterruptedException {
        if (proxy != null) {
            proxy.close();
        }
        if (replayServer != null) {
            replayServer.close();
        }
        if (timeServer != null) {
            timeServer.close();
        }
        threadPool.shutdownNow();
        threadPool.awaitTermination(5, TimeUnit.SECONDS);
    }

    @Test
    @Timeout(30)
    void proxiesTrafficThenReplaysJournal() throws Exception {
        Path journalFile = tempDirectory.resolve("capture.pcap");
        PcapJournal journal = new PcapJournal(journalFile);

        proxy = new TcpProxy(
                new InetSocketAddress("127.0.0.1", 0),
                timeServer.boundAddress(),
                journal,
                16 * 1024);
        proxy.bind();
        threadPool.submit(proxy);

        // 1. Reach the time server through the proxy.
        String viaProxy = readAll(proxy.boundAddress());
        assertFalse(viaProxy.isEmpty(), "proxy should forward the time payload");
        assertTrue(viaProxy.startsWith("TIME "), "unexpected payload: " + viaProxy);

        // Let the proxy flush the journal, then close it so it can be read back.
        proxy.close();
        Thread.sleep(200);
        journal.close();

        // 2. The journal is a real pcap file (libpcap magic + non-trivial size).
        byte[] pcap = Files.readAllBytes(journalFile);
        assertTrue(pcap.length > 24, "pcap should contain packets");
        assertEquals((byte) 0xa1, pcap[0]);
        assertEquals((byte) 0xb2, pcap[1]);
        assertEquals((byte) 0xc3, pcap[2]);
        assertEquals((byte) 0xd4, pcap[3]);

        // 3. Replay the captured server side and confirm it reproduces the bytes.
        replayServer = new ReplayServer(new InetSocketAddress("127.0.0.1", 0), journalFile);
        replayServer.bind();
        threadPool.submit(replayServer);

        String viaReplay = readAll(replayServer.boundAddress());
        assertEquals(viaProxy, viaReplay,
                "replay must reproduce exactly what the upstream server sent");
    }

    @Test
    @Timeout(30)
    void replayPreservesRequestResponseSequence() throws Exception {
        EchoLineServer echoServer = new EchoLineServer();
        echoServer.bind();
        threadPool.submit(echoServer);

        Path journalFile = tempDirectory.resolve("interactive.pcap");
        PcapJournal journal = new PcapJournal(journalFile);
        proxy = new TcpProxy(
                new InetSocketAddress("127.0.0.1", 0),
                echoServer.boundAddress(),
                journal,
                16 * 1024);
        proxy.bind();
        threadPool.submit(proxy);

        // Record a two-turn exchange through the proxy: each response comes back
        // only after its request.
        String firstResponse;
        String secondResponse;
        try (Socket socket = new Socket()) {
            socket.connect(proxy.boundAddress(), 5000);
            socket.setSoTimeout(5000);
            OutputStream output = socket.getOutputStream();
            InputStream input = socket.getInputStream();
            output.write("alpha\n".getBytes(StandardCharsets.UTF_8));
            output.flush();
            firstResponse = readLine(input);
            output.write("beta\n".getBytes(StandardCharsets.UTF_8));
            output.flush();
            secondResponse = readLine(input);
        }
        assertEquals("ECHO alpha\n", firstResponse);
        assertEquals("ECHO beta\n", secondResponse);

        proxy.close();
        echoServer.close();
        Thread.sleep(200);
        journal.close();

        // Replay: the server must wait for each request before answering.
        replayServer = new ReplayServer(new InetSocketAddress("127.0.0.1", 0), journalFile);
        replayServer.bind();
        threadPool.submit(replayServer);

        try (Socket socket = new Socket()) {
            socket.connect(replayServer.boundAddress(), 5000);
            socket.setSoTimeout(5000);
            OutputStream output = socket.getOutputStream();
            InputStream input = socket.getInputStream();

            output.write("alpha\n".getBytes(StandardCharsets.UTF_8));
            output.flush();
            assertEquals("ECHO alpha\n", readLine(input), "first response after first request");

            // The second response must NOT arrive until the second request is sent.
            socket.setSoTimeout(300);
            boolean blockedUntilRequest = false;
            try {
                input.read();
            } catch (SocketTimeoutException expected) {
                blockedUntilRequest = true;
            }
            assertTrue(blockedUntilRequest, "replay must wait for the second request");

            socket.setSoTimeout(5000);
            output.write("beta\n".getBytes(StandardCharsets.UTF_8));
            output.flush();
            assertEquals("ECHO beta\n", readLine(input), "second response after second request");
        }
    }

    /** Connect, read until EOF, return the bytes as a UTF-8 string. */
    private static String readAll(InetSocketAddress address) throws IOException {
        try (Socket socket = new Socket()) {
            socket.connect(address, 5000);
            socket.setSoTimeout(5000);
            try (InputStream input = socket.getInputStream()) {
                ByteArrayOutputStream collected = new ByteArrayOutputStream();
                byte[] buffer = new byte[256];
                int bytesRead;
                while ((bytesRead = input.read(buffer)) != -1) {
                    collected.write(buffer, 0, bytesRead);
                }
                return new String(collected.toByteArray(), StandardCharsets.UTF_8);
            }
        }
    }

    /** Read a single newline-terminated line (newline included) as UTF-8. */
    private static String readLine(InputStream input) throws IOException {
        ByteArrayOutputStream collected = new ByteArrayOutputStream();
        int value;
        while ((value = input.read()) != -1) {
            collected.write(value);
            if (value == '\n') {
                break;
            }
        }
        return new String(collected.toByteArray(), StandardCharsets.UTF_8);
    }

    /**
     * Minimal blocking upstream server: on each connection it writes
     * {@code "TIME <epochMillis>\n"} and closes. One thread per connection keeps
     * the helper trivial; it is only the test fixture, not the proxy itself.
     */
    private final class TimeServer implements Runnable, AutoCloseable {
        private ServerSocketChannel serverChannel;
        private volatile boolean running = true;
        private volatile InetSocketAddress boundAddress;

        void bind() throws IOException {
            serverChannel = ServerSocketChannel.open();
            serverChannel.bind(new InetSocketAddress("127.0.0.1", 0));
            boundAddress = (InetSocketAddress) serverChannel.getLocalAddress();
        }

        InetSocketAddress boundAddress() {
            return boundAddress;
        }

        @Override
        public void run() {
            while (running) {
                try {
                    SocketChannel connection = serverChannel.accept();
                    if (connection == null) {
                        continue;
                    }
                    threadPool.submit(() -> {
                        try (SocketChannel openConnection = connection) {
                            String time = "TIME " + System.currentTimeMillis() + "\n";
                            openConnection.write(
                                    ByteBuffer.wrap(time.getBytes(StandardCharsets.UTF_8)));
                        } catch (IOException ignored) {
                            // connection went away
                        }
                    });
                } catch (IOException exception) {
                    if (running) {
                        throw new RuntimeException(exception);
                    }
                }
            }
        }

        @Override
        public void close() {
            running = false;
            try {
                if (serverChannel != null) {
                    serverChannel.close();
                }
            } catch (IOException ignored) {
                // best effort
            }
        }
    }

    /**
     * Request-driven upstream fixture: for every newline-terminated request it
     * reads, it replies {@code "ECHO <request>"} (newline included). Loops until
     * the client closes. One thread per connection.
     */
    private final class EchoLineServer implements Runnable, AutoCloseable {
        private ServerSocketChannel serverChannel;
        private volatile boolean running = true;
        private volatile InetSocketAddress boundAddress;

        void bind() throws IOException {
            serverChannel = ServerSocketChannel.open();
            serverChannel.bind(new InetSocketAddress("127.0.0.1", 0));
            boundAddress = (InetSocketAddress) serverChannel.getLocalAddress();
        }

        InetSocketAddress boundAddress() {
            return boundAddress;
        }

        @Override
        public void run() {
            while (running) {
                try {
                    SocketChannel connection = serverChannel.accept();
                    if (connection == null) {
                        continue;
                    }
                    threadPool.submit(() -> serve(connection));
                } catch (IOException exception) {
                    if (running) {
                        throw new RuntimeException(exception);
                    }
                }
            }
        }

        private void serve(SocketChannel connection) {
            try (Socket socket = connection.socket()) {
                InputStream input = socket.getInputStream();
                OutputStream output = socket.getOutputStream();
                String line;
                while ((line = readLine(input)).endsWith("\n")) {
                    String request = line.substring(0, line.length() - 1);
                    output.write(("ECHO " + request + "\n").getBytes(StandardCharsets.UTF_8));
                    output.flush();
                }
            } catch (IOException ignored) {
                // client went away
            }
        }

        @Override
        public void close() {
            running = false;
            try {
                if (serverChannel != null) {
                    serverChannel.close();
                }
            } catch (IOException ignored) {
                // best effort
            }
        }
    }
}
