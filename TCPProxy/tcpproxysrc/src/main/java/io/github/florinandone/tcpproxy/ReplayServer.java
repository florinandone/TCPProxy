package io.github.florinandone.tcpproxy;

import java.io.Closeable;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.StandardSocketOptions;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Replays a previously captured {@link PcapJournal}, preserving the original
 * request/response sequence.
 *
 * <p>The server parses a {@code .pcap} produced by {@link PcapJournal} into one
 * ordered conversation per recorded connection. A conversation is a sequence of
 * <em>turns</em>: a turn is either bytes the client sent
 * ({@link Direction#CLIENT_TO_REMOTE}) or bytes the upstream server sent
 * ({@link Direction#REMOTE_TO_CLIENT}), with consecutive same-direction packets
 * coalesced.</p>
 *
 * <p>When a client connects it is matched to the next recorded conversation and
 * the turns are replayed in order:</p>
 * <ul>
 *   <li>a <strong>server</strong> turn is written to the client;</li>
 *   <li>a <strong>client</strong> turn makes the replay wait until the client
 *       has sent that many request bytes before moving on.</li>
 * </ul>
 *
 * <p>So a recorded response is only sent <em>after</em> the matching request
 * arrives, exactly as it happened against the real upstream. A conversation that
 * opens with a server turn (the server speaks first, e.g. a daytime/time server)
 * is answered immediately on connect.</p>
 *
 * <p>Single-threaded, non-blocking, Java 8 compatible.</p>
 */
public final class ReplayServer implements Runnable, Closeable {

    private static final int IP_HEADER_MIN = 20;

    private final InetSocketAddress listenAddress;
    private final ArrayDeque<List<Turn>> conversations;

    private volatile Selector selector;
    private volatile ServerSocketChannel server;
    private volatile boolean running;
    private volatile InetSocketAddress boundAddress;

    /**
     * @param listenAddress address to listen on
     * @param journalFile   the pcap file written earlier by {@link PcapJournal}
     */
    public ReplayServer(InetSocketAddress listenAddress, Path journalFile) throws IOException {
        this.listenAddress = listenAddress;
        this.conversations = new ArrayDeque<>(parse(journalFile));
    }

    /** Open the listening socket; call before {@link #run()} to learn the bound port. */
    public synchronized void bind() throws IOException {
        if (selector != null) {
            return;
        }
        selector = Selector.open();
        server = ServerSocketChannel.open();
        server.configureBlocking(false);
        server.setOption(StandardSocketOptions.SO_REUSEADDR, true);
        server.bind(listenAddress);
        server.register(selector, SelectionKey.OP_ACCEPT);
        boundAddress = (InetSocketAddress) server.getLocalAddress();
        running = true;
    }

    public InetSocketAddress boundAddress() {
        return boundAddress;
    }

    @Override
    public void run() {
        try {
            if (selector == null) {
                bind();
            }
            eventLoop();
        } catch (IOException e) {
            if (running) {
                throw new RuntimeException("replay server failed", e);
            }
        } finally {
            shutdown();
        }
    }

    private void eventLoop() throws IOException {
        final Selector sel = selector;
        while (running) {
            if (sel.select() == 0) {
                continue;
            }
            Set<SelectionKey> keys = sel.selectedKeys();
            Iterator<SelectionKey> it = keys.iterator();
            while (it.hasNext()) {
                SelectionKey key = it.next();
                it.remove();
                if (!key.isValid()) {
                    continue;
                }
                try {
                    if (key.isAcceptable()) {
                        accept();
                    } else {
                        Replay replay = (Replay) key.attachment();
                        if (key.isReadable()) {
                            replay.onReadable(key);
                        }
                        if (key.isValid() && key.isWritable()) {
                            replay.onWritable(key);
                        }
                    }
                } catch (IOException e) {
                    closeQuietly(key.channel());
                    key.cancel();
                }
            }
        }
    }

    private void accept() throws IOException {
        SocketChannel client;
        while ((client = server.accept()) != null) {
            client.configureBlocking(false);
            client.setOption(StandardSocketOptions.TCP_NODELAY, true);
            List<Turn> turns = conversations.isEmpty() ? null : conversations.poll();
            Replay replay = new Replay(turns);
            SelectionKey key = client.register(selector, 0, replay);
            replay.begin(key);
        }
    }

    @Override
    public void close() {
        running = false;
        Selector sel = selector;
        if (sel != null) {
            sel.wakeup();
        }
    }

    private void shutdown() {
        running = false;
        Selector sel = selector;
        if (sel != null) {
            for (SelectionKey key : sel.keys()) {
                closeQuietly(key.channel());
                key.cancel();
            }
            closeQuietly(sel);
        }
        closeQuietly(server);
        selector = null;
        server = null;
    }

    /**
     * Per-connection replay cursor: walks the recorded turns, writing server
     * turns and waiting out client turns.
     */
    private static final class Replay {
        private final List<Turn> turns;
        private int index;
        private ByteBuffer out;          // response bytes currently being written
        private int requestRemaining;    // request bytes still to read this turn
        private final ByteBuffer drain = ByteBuffer.allocate(1024);

        Replay(List<Turn> turns) {
            this.turns = turns;
        }

        /** Position on the first turn and arm the right interest set. */
        void begin(SelectionKey key) throws IOException {
            advance(key);
        }

        private void advance(SelectionKey key) throws IOException {
            SocketChannel ch = (SocketChannel) key.channel();
            while (turns != null && index < turns.size()) {
                Turn turn = turns.get(index);
                if (turn.direction == Direction.REMOTE_TO_CLIENT) {
                    out = ByteBuffer.wrap(turn.bytes);
                    key.interestOps(SelectionKey.OP_WRITE);
                    return;
                }
                // Client turn: wait for the request bytes before the next response.
                requestRemaining = turn.bytes.length;
                if (requestRemaining == 0) {
                    index++;
                    continue;
                }
                key.interestOps(SelectionKey.OP_READ);
                return;
            }
            // Conversation exhausted.
            key.cancel();
            ch.close();
        }

        void onWritable(SelectionKey key) throws IOException {
            SocketChannel ch = (SocketChannel) key.channel();
            if (out != null && out.hasRemaining()) {
                ch.write(out);
            }
            if (out == null || !out.hasRemaining()) {
                out = null;
                index++;
                advance(key);
            }
        }

        void onReadable(SelectionKey key) throws IOException {
            SocketChannel ch = (SocketChannel) key.channel();
            drain.clear();
            if (requestRemaining < drain.capacity()) {
                drain.limit(requestRemaining);
            }
            int n = ch.read(drain);
            if (n < 0) {
                key.cancel();
                ch.close();
                return;
            }
            requestRemaining -= n;
            if (requestRemaining <= 0) {
                index++;
                advance(key);
            }
        }
    }

    /** One coalesced turn of a recorded conversation. */
    private static final class Turn {
        final Direction direction;
        final byte[] bytes;

        Turn(Direction direction, byte[] bytes) {
            this.direction = direction;
            this.bytes = bytes;
        }
    }

    // ------------------------------------------------------------------
    // pcap parsing
    // ------------------------------------------------------------------

    /**
     * Parse the capture into one ordered, coalesced conversation per recorded
     * connection (keyed by client port, preserving capture order).
     */
    private static List<List<Turn>> parse(Path journalFile) throws IOException {
        ByteBuffer data;
        try (FileChannel ch = FileChannel.open(journalFile, StandardOpenOption.READ)) {
            int size = (int) ch.size();
            data = ByteBuffer.allocate(size);
            while (data.hasRemaining() && ch.read(data) >= 0) {
                // read until full
            }
            data.flip();
        }

        List<List<Turn>> result = new ArrayList<>();
        if (data.remaining() < 24) {
            return result;
        }
        int magic = data.getInt();
        ByteOrder order = (magic == 0xa1b2c3d4) ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN;
        data.order(order);
        data.position(24); // skip the rest of the global header

        // Raw per-packet payloads, grouped by connection, in capture order.
        Map<Integer, List<Turn>> byClientPort = new LinkedHashMap<>();
        while (data.remaining() >= 16) {
            data.getInt();                       // ts_sec
            data.getInt();                       // ts_usec
            int inclLen = data.getInt();
            data.getInt();                       // orig_len
            if (inclLen < 0 || data.remaining() < inclLen) {
                break;
            }
            int packetStart = data.position();
            parsePacket(data, packetStart, inclLen, byClientPort);
            data.position(packetStart + inclLen);
        }

        for (List<Turn> raw : byClientPort.values()) {
            result.add(coalesce(raw));
        }
        return result;
    }

    private static void parsePacket(ByteBuffer data, int start, int len,
                                    Map<Integer, List<Turn>> byClientPort) {
        if (len < IP_HEADER_MIN) {
            return;
        }
        int versionIhl = data.get(start) & 0xFF;
        if ((versionIhl >>> 4) != 4) {
            return;                              // only IPv4 in our captures
        }
        int ihl = (versionIhl & 0x0F) * 4;
        int totalLength = readU16(data, start + 2);
        int protocol = data.get(start + 9) & 0xFF;
        int srcIp = data.getInt(start + 12);
        if (protocol != 6 || len < ihl + 20) {
            return;                              // only TCP
        }

        boolean fromClient = srcIp == PcapJournal.CLIENT_IP;
        boolean fromRemote = srcIp == PcapJournal.REMOTE_IP;
        if (!fromClient && !fromRemote) {
            return;                              // not one of our synthetic endpoints
        }

        int tcpStart = start + ihl;
        int srcPort = readU16(data, tcpStart);
        int dstPort = readU16(data, tcpStart + 2);
        int dataOffset = ((data.get(tcpStart + 12) & 0xFF) >>> 4) * 4;
        int payloadStart = tcpStart + dataOffset;
        int payloadLen = (start + totalLength) - payloadStart;
        if (payloadLen <= 0) {
            return;                              // handshake / pure ACK / FIN
        }

        int clientPort = fromClient ? srcPort : dstPort;
        Direction direction = fromClient ? Direction.CLIENT_TO_REMOTE : Direction.REMOTE_TO_CLIENT;

        byte[] payload = new byte[payloadLen];
        for (int i = 0; i < payloadLen; i++) {
            payload[i] = data.get(payloadStart + i);
        }
        byClientPort.computeIfAbsent(clientPort, k -> new ArrayList<>())
                .add(new Turn(direction, payload));
    }

    /** Merge consecutive same-direction packets into single turns. */
    private static List<Turn> coalesce(List<Turn> raw) {
        List<Turn> turns = new ArrayList<>();
        int i = 0;
        while (i < raw.size()) {
            Direction dir = raw.get(i).direction;
            int total = 0;
            int j = i;
            while (j < raw.size() && raw.get(j).direction == dir) {
                total += raw.get(j).bytes.length;
                j++;
            }
            byte[] merged = new byte[total];
            int off = 0;
            for (int k = i; k < j; k++) {
                byte[] b = raw.get(k).bytes;
                System.arraycopy(b, 0, merged, off, b.length);
                off += b.length;
            }
            turns.add(new Turn(dir, merged));
            i = j;
        }
        return turns;
    }

    private static int readU16(ByteBuffer data, int index) {
        return ((data.get(index) & 0xFF) << 8) | (data.get(index + 1) & 0xFF);
    }

    private static void closeQuietly(Closeable c) {
        if (c != null) {
            try {
                c.close();
            } catch (IOException ignored) {
                // best effort
            }
        }
    }
}
