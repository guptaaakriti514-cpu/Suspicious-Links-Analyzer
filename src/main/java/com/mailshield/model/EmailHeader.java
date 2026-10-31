package com.mailshield.model;

import java.util.Objects;

/**
 * Represents a single RFC 5322 email header field.
 */
public final class EmailHeader {
    private final String name;
    private final String value;
    private final String rawLine;

    public EmailHeader(String name, String value, String rawLine) {
        this.name = name != null ? name.trim() : "";
        this.value = value != null ? value.trim() : "";
        this.rawLine = rawLine != null ? rawLine : (this.name + ": " + this.value);
    }

    public EmailHeader(String name, String value) {
        this(name, value, null);
    }

    public String getName() {
        return name;
    }

    public String getValue() {
        return value;
    }

    public String getRawLine() {
        return rawLine;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        EmailHeader that = (EmailHeader) o;
        return name.equalsIgnoreCase(that.name) && Objects.equals(value, that.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(name.toLowerCase(), value);
    }

    @Override
    public String toString() {
        return name + ": " + value;
    }
}

