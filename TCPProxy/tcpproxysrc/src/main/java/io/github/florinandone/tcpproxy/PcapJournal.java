package io.github.florinandone.tcpproxy;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A {@link Journal} that writes a classic libpcap capture file.
 *
 * <p>Each proxied connection becomes one synthetic TCP stream: the journal
 * fabricates a SYN / SYN-ACK / ACK handshake and then emits one TCP segment
 * per recorded chunk, with correct IPv4 and TCP checksums and monotonically
 * increasing sequence numbers. The resulting {@code .pcap} file opens directly
 * in Wireshark and supports "Follow TCP Stream".</p>
 *
 * <p>The two synthetic endpoints use fixed addresses so that a
 * {@link ReplayServer} can unambiguously tell the two directions apart:
 * the client is {@value #CLIENT_IP_STRING} and the upstream server is
 * {@value #REMOTE_IP_STRING}. Real port numbers are preserved, which keeps
 * distinct connections in distinct TCP streams.</p>
 *
 * <p>Writing is allocation-free on the hot path: a single direct scratch
 * buffer is reused for every packet.</p>
 */
public final class PcapJournal implements Journal {

    /** Link type DLT_RAW: each captured packet starts with a raw IP header. */
    private static final int LINKTYPE_RAW = 101;
    private static final int PCAP_MAGIC = 0xa1b2c3d4;
    private static final int SNAPLEN = 65535;

    private static final int IP_HEADER_LEN = 20;
    private static final int TCP_HEADER_LEN = 20;
    private static final int MAX_PAYLOAD = SNAPLEN - IP_HEADER_LEN - TCP_HEADER_LEN;

    /** Synthetic IPv4 address of the client side of every stream. */
    public static final int CLIENT_IP = ip(10, 0, 0, 1);
    /** Synthetic IPv4 address of the upstream-server side of every stream. */
    public static final int REMOTE_IP = ip(10, 0, 0, 2);
    static final String CLIENT_IP_STRING = "10.0.0.1";
    static final String REMOTE_IP_STRING = "10.0.0.2";

    private static final byte FIN = 0x01;
    private static final byte SYN = 0x02;
    private static final byte ACK = 0x10;
    private static final byte PSH = 0x08;

    private final FileChannel channel;
    private final ByteBuffer scratch =
            ByteBuffer.allocateDirect(16 + IP_HEADER_LEN + TCP_HEADER_LEN + MAX_PAYLOAD)
                    .order(ByteOrder.BIG_ENDIAN);
    private final AtomicInteger ipId = new AtomicInteger(1);

    public PcapJournal(Path file) throws IOException {
        this.channel = FileChannel.open(file,
                StandardOpenOption.CREATE, StandardOpenOption.WRITE,
                StandardOpenOption.TRUNCATE_EXISTING);
        writeGlobalHeader();
    }

    private void writeGlobalHeader() throws IOException {
        ByteBuffer h = ByteBuffer.allocate(24).order(ByteOrder.BIG_ENDIAN);
        h.putInt(PCAP_MAGIC);
        h.putShort((short) 2);          // version major
        h.putShort((short) 4);          // version minor
        h.putInt(0);                    // thiszone
        h.putInt(0);                    // sigfigs
        h.putInt(SNAPLEN);              // snaplen
        h.putInt(LINKTYPE_RAW);         // network
        h.flip();
        writeFully(h);
    }

    @Override
    public Stream openStream(InetSocketAddress client, InetSocketAddress remote) {
        PcapStream stream = new PcapStream(client.getPort(), remote.getPort());
        stream.handshake();
        return stream;
    }

    @Override
    public void close() throws IOException {
        channel.close();
    }

    /** One synthetic TCP conversation. Only ever touched by the proxy thread. */
    private final class PcapStream implements Stream {
        private final int clientPort;
        private final int remotePort;
        private long seqClient = 1000;   // next seq for client -> remote
        private long seqRemote = 5000;   // next seq for remote -> client
        private boolean closed;

        PcapStream(int clientPort, int remotePort) {
            this.clientPort = clientPort;
            this.remotePort = remotePort;
        }

        void handshake() {
            // SYN (client -> remote)
            emit(Direction.CLIENT_TO_REMOTE, SYN, null, 0, 0, seqClient, 0);
            seqClient += 1;
            // SYN-ACK (remote -> client)
            emit(Direction.REMOTE_TO_CLIENT, (byte) (SYN | ACK), null, 0, 0, seqRemote, seqClient);
            seqRemote += 1;
            // ACK (client -> remote)
            emit(Direction.CLIENT_TO_REMOTE, ACK, null, 0, 0, seqClient, seqRemote);
        }

        @Override
        public void record(Direction direction, ByteBuffer data, int offset, int length) {
            int pos = offset;
            int remaining = length;
            while (remaining > 0) {
                int chunk = Math.min(remaining, MAX_PAYLOAD);
                if (direction == Direction.CLIENT_TO_REMOTE) {
                    emit(direction, (byte) (PSH | ACK), data, pos, chunk, seqClient, seqRemote);
                    seqClient += chunk;
                } else {
                    emit(direction, (byte) (PSH | ACK), data, pos, chunk, seqRemote, seqClient);
                    seqRemote += chunk;
                }
                pos += chunk;
                remaining -= chunk;
            }
        }

        @Override
        public void close() {
            if (closed) {
                return;
            }
            closed = true;
            // Graceful FIN/ACK from both sides so the capture is self-contained.
            emit(Direction.REMOTE_TO_CLIENT, (byte) (FIN | ACK), null, 0, 0, seqRemote, seqClient);
            seqRemote += 1;
            emit(Direction.CLIENT_TO_REMOTE, (byte) (FIN | ACK), null, 0, 0, seqClient, seqRemote);
            seqClient += 1;
        }

        private void emit(Direction direction, byte flags, ByteBuffer data,
                          int offset, int length, long seq, long ack) {
            int srcIp;
            int dstIp;
            int srcPort;
            int dstPort;
            if (direction == Direction.CLIENT_TO_REMOTE) {
                srcIp = CLIENT_IP; dstIp = REMOTE_IP;
                srcPort = clientPort; dstPort = remotePort;
            } else {
                srcIp = REMOTE_IP; dstIp = CLIENT_IP;
                srcPort = remotePort; dstPort = clientPort;
            }
            writePacket(srcIp, dstIp, srcPort, dstPort, flags, seq, ack, data, offset, length);
        }
    }

    /**
     * Assemble a single pcap record (record header + IPv4 + TCP + payload) into
     * the reusable scratch buffer and flush it to disk.
     */
    private synchronized void writePacket(int srcIp, int dstIp, int srcPort, int dstPort,
                                          byte flags, long seq, long ack,
                                          ByteBuffer data, int offset, int length) {
        int ipTotal = IP_HEADER_LEN + TCP_HEADER_LEN + length;
        ByteBuffer b = scratch;
        b.clear();

        // --- pcap record header ---
        long micros = System.currentTimeMillis() * 1000L;
        b.putInt((int) (micros / 1_000_000L));      // ts_sec
        b.putInt((int) (micros % 1_000_000L));      // ts_usec
        b.putInt(ipTotal);                          // incl_len
        b.putInt(ipTotal);                          // orig_len

        int ipStart = b.position();
        // --- IPv4 header ---
        b.put((byte) 0x45);                         // version 4, IHL 5
        b.put((byte) 0x00);                         // DSCP/ECN
        b.putShort((short) ipTotal);                // total length
        b.putShort((short) (ipId.getAndIncrement() & 0xFFFF));
        b.putShort((short) 0x4000);                 // flags: don't fragment
        b.put((byte) 64);                           // TTL
        b.put((byte) 6);                            // protocol: TCP
        int ipChecksumPos = b.position();
        b.putShort((short) 0);                      // checksum placeholder
        b.putInt(srcIp);
        b.putInt(dstIp);

        int tcpStart = b.position();
        // --- TCP header ---
        b.putShort((short) srcPort);
        b.putShort((short) dstPort);
        b.putInt((int) seq);
        b.putInt((int) ack);
        b.put((byte) 0x50);                         // data offset 5 words, reserved 0
        b.put(flags);
        b.putShort((short) 0xFFFF);                 // window
        int tcpChecksumPos = b.position();
        b.putShort((short) 0);                      // checksum placeholder
        b.putShort((short) 0);                      // urgent pointer

        // --- payload ---
        for (int i = 0; i < length; i++) {
            b.put(data.get(offset + i));
        }

        // --- checksums (computed over the assembled bytes) ---
        putShort(b, ipChecksumPos, ipChecksum(b, ipStart));
        putShort(b, tcpChecksumPos,
                tcpChecksum(b, srcIp, dstIp, tcpStart, TCP_HEADER_LEN + length));

        b.flip();
        try {
            writeFully(b);
        } catch (IOException e) {
            throw new JournalWriteException(e);
        }
    }

    private void writeFully(ByteBuffer b) throws IOException {
        while (b.hasRemaining()) {
            channel.write(b);
        }
    }

    private static void putShort(ByteBuffer b, int index, int value) {
        b.put(index, (byte) (value >>> 8));
        b.put(index + 1, (byte) value);
    }

    private static int ipChecksum(ByteBuffer b, int start) {
        long sum = sumWords(b, start, IP_HEADER_LEN);
        return fold(sum);
    }

    private static int tcpChecksum(ByteBuffer b, int srcIp, int dstIp, int tcpStart, int tcpLen) {
        // IPv4 pseudo-header: src, dst, zero, protocol, TCP length.
        long sum = 0;
        sum += (srcIp >>> 16) & 0xFFFF;
        sum += srcIp & 0xFFFF;
        sum += (dstIp >>> 16) & 0xFFFF;
        sum += dstIp & 0xFFFF;
        sum += 6;                 // protocol
        sum += tcpLen & 0xFFFF;
        sum += sumWords(b, tcpStart, tcpLen);
        return fold(sum);
    }

    private static long sumWords(ByteBuffer b, int start, int len) {
        long sum = 0;
        int i = start;
        int end = start + (len & ~1);
        while (i < end) {
            sum += ((b.get(i) & 0xFF) << 8) | (b.get(i + 1) & 0xFF);
            i += 2;
        }
        if ((len & 1) != 0) {
            sum += (b.get(end) & 0xFF) << 8;   // pad final odd byte with zero
        }
        return sum;
    }

    private static int fold(long sum) {
        while ((sum >>> 16) != 0) {
            sum = (sum & 0xFFFF) + (sum >>> 16);
        }
        return (int) (~sum) & 0xFFFF;
    }

    private static int ip(int a, int b, int c, int d) {
        return (a << 24) | (b << 16) | (c << 8) | d;
    }

    /** Unchecked wrapper so the allocation-free record path stays exception-clean. */
    public static final class JournalWriteException extends RuntimeException {
        JournalWriteException(IOException cause) {
            super(cause);
        }
    }
}
