package com.mailshield.ingestion;

import com.mailshield.model.EmailMessage;
import com.mailshield.model.ProviderType;

import java.io.InputStream;

/**
 * Service contract for safe RFC 5322 and pasted email ingestion.
 */
public interface EmailParser {

    /**
     * Parse raw email text (headers and body) pasted by the user.
     *
     * @param rawText the raw email text
     * @return normalized immutable EmailMessage
     * @throws EmailParsingException if parsing fails due to unrecoverable malformation
     */
    EmailMessage parseRawText(String rawText) throws EmailParsingException;

    /**
     * Parse an RFC 5322 format .eml input stream.
     *
     * @param inputStream the .eml stream
     * @param sourceDescription origin description (e.g., filename)
     * @return normalized immutable EmailMessage
     * @throws EmailParsingException if parsing fails
     */
    EmailMessage parseEmlStream(InputStream inputStream, String sourceDescription) throws EmailParsingException;
}

