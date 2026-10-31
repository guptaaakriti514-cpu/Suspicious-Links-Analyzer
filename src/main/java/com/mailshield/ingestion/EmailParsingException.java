package com.mailshield.ingestion;

public class EmailParsingException extends Exception {
    public EmailParsingException(String message) {
        super(message);
    }

    public EmailParsingException(String message, Throwable cause) {
        super(message, cause);
    }
}

