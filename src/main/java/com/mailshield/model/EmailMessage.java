package com.mailshield.model;

import java.time.Instant;
import java.util.*;

/**
 * Normalized immutable representation of an email message across all ingestion sources
 * (Manual Paste, .eml File, Gmail API, Outlook Graph API, Demo Fixtures).
 */
public final class EmailMessage {
    private final String id;
    private final String providerMessageId;
    private final ProviderType providerSource;
    private final String from;
    private final String fromDisplayName;
    private final String fromAddress;
    private final String replyTo;
    private final String returnPath;
    private final List<String> to;
    private final List<String> cc;
    private final List<String> bcc;
    private final String subject;
    private final Instant date;
    private final String messageIdHeader;
    private final List<EmailHeader> headers;
    private final String bodyText;
    private final String bodyHtml;
    private final List<EmailAttachmentMetadata> attachments;
    private final List<ExtractedUrl> extractedUrls;
    private final AuthenticationResult authResult;
    private final byte[] rawBytes;
    private final String rawSha256;
    private final Instant ingestedAt;

    public EmailMessage(Builder builder) {
        this.id = builder.id != null ? builder.id : UUID.randomUUID().toString();
        this.providerMessageId = builder.providerMessageId != null ? builder.providerMessageId : this.id;
        this.providerSource = builder.providerSource != null ? builder.providerSource : ProviderType.MANUAL_PASTE;
        this.from = builder.from != null ? builder.from : "";
        this.fromDisplayName = builder.fromDisplayName != null ? builder.fromDisplayName : "";
        this.fromAddress = builder.fromAddress != null ? builder.fromAddress.toLowerCase().trim() : "";
        this.replyTo = builder.replyTo != null ? builder.replyTo.toLowerCase().trim() : "";
        this.returnPath = builder.returnPath != null ? builder.returnPath.toLowerCase().trim() : "";
        this.to = Collections.unmodifiableList(new ArrayList<>(builder.to));
        this.cc = Collections.unmodifiableList(new ArrayList<>(builder.cc));
        this.bcc = Collections.unmodifiableList(new ArrayList<>(builder.bcc));
        this.subject = builder.subject != null ? builder.subject : "(No Subject)";
        this.date = builder.date != null ? builder.date : Instant.now();
        this.messageIdHeader = builder.messageIdHeader != null ? builder.messageIdHeader : "";
        this.headers = Collections.unmodifiableList(new ArrayList<>(builder.headers));
        this.bodyText = builder.bodyText != null ? builder.bodyText : "";
        this.bodyHtml = builder.bodyHtml != null ? builder.bodyHtml : "";
        this.attachments = Collections.unmodifiableList(new ArrayList<>(builder.attachments));
        this.extractedUrls = Collections.unmodifiableList(new ArrayList<>(builder.extractedUrls));
        this.authResult = builder.authResult != null ? builder.authResult : AuthenticationResult.missing();
        this.rawBytes = builder.rawBytes != null ? builder.rawBytes.clone() : new byte[0];
        this.rawSha256 = builder.rawSha256 != null ? builder.rawSha256.toLowerCase() : "";
        this.ingestedAt = builder.ingestedAt != null ? builder.ingestedAt : Instant.now();
    }

    public static Builder builder() {
        return new Builder();
    }

    public String getId() {
        return id;
    }

    public String getProviderMessageId() {
        return providerMessageId;
    }

    public ProviderType getProviderSource() {
        return providerSource;
    }

    public String getFrom() {
        return from;
    }

    public String getFromDisplayName() {
        return fromDisplayName;
    }

    public String getFromAddress() {
        return fromAddress;
    }

    public String getReplyTo() {
        return replyTo;
    }

    public String getReturnPath() {
        return returnPath;
    }

    public List<String> getTo() {
        return to;
    }

    public List<String> getCc() {
        return cc;
    }

    public List<String> getBcc() {
        return bcc;
    }

    public String getSubject() {
        return subject;
    }

    public Instant getDate() {
        return date;
    }

    public String getMessageIdHeader() {
        return messageIdHeader;
    }

    public List<EmailHeader> getHeaders() {
        return headers;
    }

    public String getHeaderValue(String name) {
        if (name == null) return null;
        for (EmailHeader h : headers) {
            if (h.getName().equalsIgnoreCase(name)) {
                return h.getValue();
            }
        }
        return null;
    }

    public List<String> getHeaderValues(String name) {
        if (name == null) return Collections.emptyList();
        List<String> result = new ArrayList<>();
        for (EmailHeader h : headers) {
            if (h.getName().equalsIgnoreCase(name)) {
                result.add(h.getValue());
            }
        }
        return result;
    }

    public String getBodyText() {
        return bodyText;
    }

    public String getBodyHtml() {
        return bodyHtml;
    }

    public List<EmailAttachmentMetadata> getAttachments() {
        return attachments;
    }

    public List<ExtractedUrl> getExtractedUrls() {
        return extractedUrls;
    }

    public AuthenticationResult getAuthResult() {
        return authResult;
    }

    public byte[] getRawBytes() {
        return rawBytes != null ? rawBytes.clone() : new byte[0];
    }

    public String getRawSha256() {
        return rawSha256;
    }

    public Instant getIngestedAt() {
        return ingestedAt;
    }

    public String getSenderDomain() {
        if (fromAddress == null || !fromAddress.contains("@")) return "";
        int atIdx = fromAddress.lastIndexOf('@');
        return fromAddress.substring(atIdx + 1).trim().toLowerCase();
    }

    public static class Builder {
        private String id;
        private String providerMessageId;
        private ProviderType providerSource = ProviderType.MANUAL_PASTE;
        private String from = "";
        private String fromDisplayName = "";
        private String fromAddress = "";
        private String replyTo = "";
        private String returnPath = "";
        private List<String> to = new ArrayList<>();
        private List<String> cc = new ArrayList<>();
        private List<String> bcc = new ArrayList<>();
        private String subject = "";
        private Instant date = Instant.now();
        private String messageIdHeader = "";
        private List<EmailHeader> headers = new ArrayList<>();
        private String bodyText = "";
        private String bodyHtml = "";
        private List<EmailAttachmentMetadata> attachments = new ArrayList<>();
        private List<ExtractedUrl> extractedUrls = new ArrayList<>();
        private AuthenticationResult authResult = AuthenticationResult.missing();
        private byte[] rawBytes = new byte[0];
        private String rawSha256 = "";
        private Instant ingestedAt = Instant.now();

        public Builder id(String id) { this.id = id; return this; }
        public Builder providerMessageId(String id) { this.providerMessageId = id; return this; }
        public Builder providerSource(ProviderType type) { this.providerSource = type; return this; }
        public Builder from(String from) { this.from = from; return this; }
        public Builder fromDisplayName(String name) { this.fromDisplayName = name; return this; }
        public Builder fromAddress(String address) { this.fromAddress = address; return this; }
        public Builder replyTo(String replyTo) { this.replyTo = replyTo; return this; }
        public Builder returnPath(String returnPath) { this.returnPath = returnPath; return this; }
        public Builder to(List<String> to) { if (to != null) this.to = new ArrayList<>(to); return this; }
        public Builder cc(List<String> cc) { if (cc != null) this.cc = new ArrayList<>(cc); return this; }
        public Builder bcc(List<String> bcc) { if (bcc != null) this.bcc = new ArrayList<>(bcc); return this; }
        public Builder subject(String subject) { this.subject = subject; return this; }
        public Builder date(Instant date) { this.date = date; return this; }
        public Builder messageIdHeader(String id) { this.messageIdHeader = id; return this; }
        public Builder headers(List<EmailHeader> headers) { if (headers != null) this.headers = new ArrayList<>(headers); return this; }
        public Builder bodyText(String text) { this.bodyText = text; return this; }
        public Builder bodyHtml(String html) { this.bodyHtml = html; return this; }
        public Builder attachments(List<EmailAttachmentMetadata> att) { if (att != null) this.attachments = new ArrayList<>(att); return this; }
        public Builder extractedUrls(List<ExtractedUrl> urls) { if (urls != null) this.extractedUrls = new ArrayList<>(urls); return this; }
        public Builder authResult(AuthenticationResult res) { this.authResult = res; return this; }
        public Builder rawBytes(byte[] bytes) { this.rawBytes = bytes; return this; }
        public Builder rawSha256(String sha256) { this.rawSha256 = sha256; return this; }
        public Builder ingestedAt(Instant at) { this.ingestedAt = at; return this; }

        public EmailMessage build() {
            return new EmailMessage(this);
        }
    }
}

