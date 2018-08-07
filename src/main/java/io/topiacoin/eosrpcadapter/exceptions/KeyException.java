package io.topiacoin.eosrpcadapter.exceptions;

import io.topiacoin.eosrpcadapter.messages.ErrorResponse;

public class KeyException extends EOSException {

    public KeyException(String message) {
        super(message);
    }

    public KeyException(String message, Throwable cause) {
        super(message, cause);
    }

}
