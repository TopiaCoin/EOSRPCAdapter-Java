package io.topiacoin.eosrpcadapter.exceptions;

import io.topiacoin.eosrpcadapter.messages.ErrorResponse;

public class WalletException extends EOSException {
    /**
     * Constructs a new exception with {@code null} as its detail message. The cause is not initialized, and may
     * subsequently be initialized by a call to {@link #initCause}.
     * @param details
     */
    public WalletException(ErrorResponse details) {
        super(details);
    }

    /**
     * Constructs a new exception with the specified detail message.  The cause is not initialized, and may subsequently be
     * initialized by a call to {@link #initCause}.
     *
     * @param message the detail message. The detail message is saved for later retrieval by the {@link #getMessage()}
     *                method.
     */
    public WalletException(String message, ErrorResponse details) {
        super(message, details);
    }

    /**
     * Constructs a new exception with the specified detail message and cause.  <p>Note that the detail message associated
     * with {@code cause} is <i>not</i> automatically incorporated in this exception's detail message.
     *
     * @param message the detail message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause   the cause (which is saved for later retrieval by the {@link #getCause()} method).  (A <tt>null</tt>
     *                value is permitted, and indicates that the cause is nonexistent or unknown.)
     *
     * @since 1.4
     */
    public WalletException(String message, Throwable cause, ErrorResponse details) {
        super(message, cause, details);
    }

    /**
     * Constructs a new exception with the specified cause and a detail message of <tt>(cause==null ? null :
     * cause.toString())</tt> (which typically contains the class and detail message of <tt>cause</tt>). This constructor is
     * useful for exceptions that are little more than wrappers for other throwables.
     *
     * @param cause the cause (which is saved for later retrieval by the {@link #getCause()} method).  (A <tt>null</tt>
     *              value is permitted, and indicates that the cause is nonexistent or unknown.)
     *
     * @since 1.4
     */
    public WalletException(Throwable cause, ErrorResponse details) {
        super(cause, details);
    }
}
