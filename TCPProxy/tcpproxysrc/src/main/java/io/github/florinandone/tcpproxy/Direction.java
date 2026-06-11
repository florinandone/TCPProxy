package io.github.florinandone.tcpproxy;

/**
 * Direction of a chunk of bytes flowing through the proxy, relative to the
 * connection that the client originally initiated.
 */
public enum Direction {
    /** Bytes sent by the client, travelling towards the remote server. */
    CLIENT_TO_REMOTE,
    /** Bytes sent by the remote server, travelling back towards the client. */
    REMOTE_TO_CLIENT
}
