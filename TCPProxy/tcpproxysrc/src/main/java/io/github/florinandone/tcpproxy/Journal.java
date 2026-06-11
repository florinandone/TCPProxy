package io.github.florinandone.tcpproxy;

import java.io.Closeable;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;

/**
 * Sink for the traffic observed by a {@link TcpProxy}.
 *
 * <p>A journal is opened once per proxy. For every accepted connection the
 * proxy calls {@link #openStream(InetSocketAddress, InetSocketAddress)} and
 * then feeds each chunk of payload through the returned {@link Stream}.</p>
 *
 * <p>Implementations are expected to be allocation-free on the recording hot
 * path: the {@link Stream#record} method receives a slice of a buffer that the
 * proxy reuses, so implementations must consume the bytes synchronously and
 * must not retain the supplied {@link ByteBuffer}.</p>
 */
public interface Journal extends Closeable {

    /**
     * Open a recording stream for a single proxied connection.
     *
     * @param client the remote address of the connecting client
     * @param remote the address of the upstream server the proxy forwards to
     * @return a per-connection stream, never {@code null}
     */
    Stream openStream(InetSocketAddress client, InetSocketAddress remote);

    /** Per-connection recording stream. */
    interface Stream extends Closeable {
        /**
         * Record a chunk of payload bytes.
         *
         * @param direction which way the bytes are flowing
         * @param data      buffer holding the bytes; not retained by the callee
         * @param offset    absolute index of the first byte to record
         * @param length    number of bytes to record
         */
        void record(Direction direction, ByteBuffer data, int offset, int length);
    }

    /** A journal that discards everything; the default when no journal is wanted. */
    Journal NONE = new Journal() {
        private final Stream stream = new Stream() {
            @Override
            public void record(Direction direction, ByteBuffer data, int offset, int length) { }

            @Override
            public void close() { }
        };

        @Override
        public Stream openStream(InetSocketAddress client, InetSocketAddress remote) {
            return stream;
        }

        @Override
        public void close() { }
    };
}
