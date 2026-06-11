package io.github.florinandone.tcpproxy;

import java.io.Closeable;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.StandardSocketOptions;
import java.nio.ByteBuffer;
import java.nio.channels.CancelledKeyException;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.util.Iterator;
import java.util.Set;

/**
 * A single-threaded, non-blocking TCP proxy.
 *
 * <p>The proxy listens on a local address and forwards every accepted
 * connection to a fixed remote address, pumping bytes in both directions. All
 * I/O runs on one selector thread, which makes the data path lock-free.</p>
 *
 * <h2>Zero garbage on the data path</h2>
 * <p>Each connection owns two direct {@link ByteBuffer}s (one per direction)
 * that are allocated once when the connection is established and reused for its
 * whole lifetime. Forwarding reads straight from one socket into the buffer
 * destined for the peer socket; there is no intermediate copy and no
 * per-read allocation. Flow control is handled by toggling {@code OP_READ} and
 * {@code OP_WRITE} interest: the proxy stops reading a socket whenever the
 * peer's outbound buffer is full, so a slow consumer naturally throttles a fast
 * producer without buffering unbounded data.</p>
 *
 * <h2>Best-practice NIO</h2>
 * <ul>
 *   <li>Non-blocking channels driven by a single {@link Selector}.</li>
 *   <li>Interest-ops reflect exactly what each socket can usefully do next.</li>
 *   <li>Partial writes are retained and retried on {@code OP_WRITE}.</li>
 *   <li>Half-close is honoured: EOF on one side is forwarded once the pending
 *       bytes for the peer have drained.</li>
 * </ul>
 *
 * <p>Java 8 compatible.</p>
 */
public final class TcpProxy implements Runnable, Closeable {

    private final InetSocketAddress listenAddress;
    private final InetSocketAddress remoteAddress;
    private final Journal journal;
    private final int bufferSize;

    private volatile Selector selector;
    private volatile ServerSocketChannel server;
    private volatile boolean running;
    private volatile InetSocketAddress boundAddress;

    /**
     * @param listenAddress address to accept client connections on
     * @param remoteAddress upstream address to forward connections to
     * @param journal       sink for observed traffic; use {@link Journal#NONE} for none
     * @param bufferSize    per-direction buffer size in bytes
     */
    public TcpProxy(InetSocketAddress listenAddress, InetSocketAddress remoteAddress,
                    Journal journal, int bufferSize) {
        if (bufferSize <= 0) {
            throw new IllegalArgumentException("bufferSize must be positive");
        }
        this.listenAddress = listenAddress;
        this.remoteAddress = remoteAddress;
        this.journal = journal == null ? Journal.NONE : journal;
        this.bufferSize = bufferSize;
    }

    /** Convenience constructor with a 16 KiB per-direction buffer and no journal. */
    public TcpProxy(InetSocketAddress listenAddress, InetSocketAddress remoteAddress) {
        this(listenAddress, remoteAddress, Journal.NONE, 16 * 1024);
    }

    /** Open the listening socket. Call before {@link #run()} to learn the bound port. */
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

    /** The address the proxy is actually listening on (resolves an ephemeral port). */
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
                throw new RuntimeException("proxy event loop failed", e);
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
                    } else if (key.isConnectable()) {
                        finishConnect(key);
                    } else {
                        Endpoint endpoint = (Endpoint) key.attachment();
                        if (key.isReadable()) {
                            endpoint.onReadable();
                        }
                        if (key.isValid() && key.isWritable()) {
                            endpoint.onWritable();
                        }
                    }
                } catch (CancelledKeyException ignored) {
                    // Peer closed the connection while we were iterating.
                } catch (IOException e) {
                    Object att = key.attachment();
                    if (att instanceof Endpoint) {
                        ((Endpoint) att).connection.close();
                    } else {
                        key.cancel();
                    }
                }
            }
        }
    }

    private void accept() throws IOException {
        SocketChannel client;
        while ((client = server.accept()) != null) {
            client.configureBlocking(false);
            client.setOption(StandardSocketOptions.TCP_NODELAY, true);
            SocketChannel remote = SocketChannel.open();
            remote.configureBlocking(false);
            remote.setOption(StandardSocketOptions.TCP_NODELAY, true);
            Connection connection = new Connection(client, remote);
            boolean connected = remote.connect(remoteAddress);
            if (connected) {
                connection.activate();
            } else {
                remote.register(selector, SelectionKey.OP_CONNECT, connection);
            }
        }
    }

    private void finishConnect(SelectionKey key) throws IOException {
        Connection connection = (Connection) key.attachment();
        try {
            if (connection.remoteChannel.finishConnect()) {
                connection.activate();
            }
        } catch (IOException e) {
            connection.close();
        }
    }

    /** Stop the event loop and release resources. Safe to call from any thread. */
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
                Object att = key.attachment();
                if (att instanceof Connection) {
                    ((Connection) att).close();
                } else if (att instanceof Endpoint) {
                    ((Endpoint) att).connection.close();
                }
                key.cancel();
            }
            closeQuietly(sel);
        }
        closeQuietly(server);
        selector = null;
        server = null;
    }

    /** A proxied client/remote pair plus the two reusable direction buffers. */
    private final class Connection {
        final SocketChannel clientChannel;
        final SocketChannel remoteChannel;
        final Endpoint client;
        final Endpoint remote;
        private Journal.Stream stream;
        private boolean closed;

        Connection(SocketChannel clientChannel, SocketChannel remoteChannel) {
            this.clientChannel = clientChannel;
            this.remoteChannel = remoteChannel;
            ByteBuffer toClient = ByteBuffer.allocateDirect(bufferSize);
            ByteBuffer toRemote = ByteBuffer.allocateDirect(bufferSize);
            this.client = new Endpoint(this, clientChannel, toClient, Direction.CLIENT_TO_REMOTE);
            this.remote = new Endpoint(this, remoteChannel, toRemote, Direction.REMOTE_TO_CLIENT);
            this.client.peer = this.remote;
            this.remote.peer = this.client;
        }

        /** Register both sockets for reads once the upstream connection is up. */
        void activate() throws IOException {
            InetSocketAddress clientAddr = (InetSocketAddress) clientChannel.getRemoteAddress();
            InetSocketAddress remoteAddr = (InetSocketAddress) remoteChannel.getRemoteAddress();
            this.stream = journal.openStream(clientAddr, remoteAddr);
            client.key = clientChannel.register(selector, SelectionKey.OP_READ, client);
            remote.key = remoteChannel.register(selector, SelectionKey.OP_READ, remote);
            client.updateInterest();
            remote.updateInterest();
        }

        void record(Direction direction, ByteBuffer data, int offset, int length) {
            if (stream != null) {
                stream.record(direction, data, offset, length);
            }
        }

        void close() {
            if (closed) {
                return;
            }
            closed = true;
            if (client.key != null) {
                client.key.cancel();
            }
            if (remote.key != null) {
                remote.key.cancel();
            }
            closeQuietly(clientChannel);
            closeQuietly(remoteChannel);
            if (stream != null) {
                closeQuietly(stream);
            }
        }
    }

    /**
     * One side of a connection. {@code outBuffer} holds bytes waiting to be
     * written to {@code channel}; those bytes are produced by reads on the peer.
     * The buffer is kept in fill mode (position == number of pending bytes).
     */
    private final class Endpoint {
        final Connection connection;
        final SocketChannel channel;
        final ByteBuffer outBuffer;
        final Direction readDirection;
        Endpoint peer;
        SelectionKey key;
        private boolean readClosed;
        private boolean closeWhenDrained;

        Endpoint(Connection connection, SocketChannel channel,
                 ByteBuffer outBuffer, Direction readDirection) {
            this.connection = connection;
            this.channel = channel;
            this.outBuffer = outBuffer;
            this.readDirection = readDirection;
        }

        void onReadable() throws IOException {
            ByteBuffer dst = peer.outBuffer;       // bytes we read go out the peer socket
            if (!dst.hasRemaining()) {
                updateInterest();
                return;
            }
            int before = dst.position();
            int n = channel.read(dst);
            if (n > 0) {
                connection.record(readDirection, dst, before, n);
                peer.flush();
            } else if (n < 0) {
                readClosed = true;
                if (peer.flush()) {
                    peer.finishOutput();
                }
            }
            updateInterest();
            peer.updateInterest();
        }

        void onWritable() throws IOException {
            if (flush() && closeWhenDrained) {
                finishOutput();
            }
            updateInterest();
            peer.updateInterest();
        }

        /**
         * Write as much of {@code outBuffer} as the socket accepts.
         *
         * @return {@code true} when nothing remains to be written
         */
        boolean flush() throws IOException {
            ByteBuffer buf = outBuffer;
            if (buf.position() == 0) {
                return true;
            }
            buf.flip();
            channel.write(buf);
            buf.compact();
            return buf.position() == 0;
        }

        /** Half-close this socket's output, or close the connection if both ends are done. */
        void finishOutput() throws IOException {
            if (readClosed && peer.readClosed) {
                connection.close();
                return;
            }
            if (channel.isOpen()) {
                try {
                    channel.shutdownOutput();
                } catch (IOException ignored) {
                    connection.close();
                }
            }
        }

        void updateInterest() {
            if (key == null || !key.isValid()) {
                return;
            }
            int ops = 0;
            if (!readClosed && peer.outBuffer.hasRemaining()) {
                ops |= SelectionKey.OP_READ;
            }
            if (outBuffer.position() > 0) {
                ops |= SelectionKey.OP_WRITE;
                if (peer.readClosed) {
                    closeWhenDrained = true;
                }
            }
            key.interestOps(ops);
        }
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
