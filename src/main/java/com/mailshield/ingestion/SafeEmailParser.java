package com.mailshield.ingestion;

import com.mailshield.detection.UrlAnalyzer;
import com.mailshield.model.*;
import com.mailshield.util.SecurityUtils;
import jakarta.mail.*;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;
import jakarta.mail.internet.MimeMultipart;
import jakarta.mail.internet.MimePart;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Robust, secure email ingestion parser using Jakarta Mail.
 * Safely parses RFC 5322 streams, pasted text, MIME hierarchies, and attachment metadata.
 * Untrusted data is never executed.
 */
public class SafeEmailParser implements EmailParser {

    private static final Logger log = LoggerFactory.getLogger(SafeEmailParser.class);
    private static final long MAX_ALLOWED_STREAM_BYTES = 25 * 1024 * 1024; // 25 MB safety limit

    private final UrlAnalyzer urlAnalyzer;

    public SafeEmailParser(UrlAnalyzer urlAnalyzer) {
        this.urlAnalyzer = urlAnalyzer;
    }

    public SafeEmailParser() {
        this(null);
    }

    @Override
    public EmailMessage parseRawText(String rawText) throws EmailParsingException {
        if (rawText == null || rawText.isBlank()) {
            throw new EmailParsingException("Email text cannot be empty.");
        }
        byte[] bytes = rawText.getBytes(StandardCharsets.UTF_8);
        return parseBytes(bytes, ProviderType.MANUAL_PASTE, "User Pasted Content");
    }

    @Override
    public EmailMessage parseEmlStream(InputStream inputStream, String sourceDescription) throws EmailParsingException {
        if (inputStream == null) {
            throw new EmailParsingException("Input stream is null.");
        }
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int read;
            long total = 0;
            while ((read = inputStream.read(buffer)) != -1) {
                total += read;
                if (total > MAX_ALLOWED_STREAM_BYTES) {
                    throw new EmailParsingException("Email file exceeds safety size limit of 25MB.");
                }
                baos.write(buffer, 0, read);
            }
            byte[] bytes = baos.toByteArray();
            return parseBytes(bytes, ProviderType.EML_FILE, sourceDescription != null ? sourceDescription : "EML Import");
        } catch (IOException e) {
            throw new EmailParsingException("Failed to read EML stream: " + e.getMessage(), e);
        }
    }

    public EmailMessage parseBytes(byte[] rawBytes, ProviderType providerType, String sourceDesc) throws EmailParsingException {
        try {
            Session session = Session.getDefaultInstance(new Properties());
            MimeMessage mimeMessage = new MimeMessage(session, new ByteArrayInputStream(rawBytes));

            EmailMessage.Builder builder = EmailMessage.builder();
            builder.providerSource(providerType);
            builder.rawBytes(rawBytes);
            builder.rawSha256(SecurityUtils.sha256Hex(rawBytes));
            builder.ingestedAt(Instant.now());

            // Extract Headers
            List<EmailHeader> headerList = new ArrayList<>();
            Enumeration<Header> allHeaders = mimeMessage.getAllHeaders();
            String messageIdHeader = "";
            String returnPath = "";

            while (allHeaders.hasMoreElements()) {
                Header h = allHeaders.nextElement();
                EmailHeader eh = new EmailHeader(h.getName(), h.getValue());
                headerList.add(eh);
                if (h.getName().equalsIgnoreCase("Message-ID")) {
                    messageIdHeader = h.getValue();
                } else if (h.getName().equalsIgnoreCase("Return-Path")) {
                    returnPath = cleanAddress(h.getValue());
                }
            }
            builder.headers(headerList);
            builder.messageIdHeader(messageIdHeader);
            builder.returnPath(returnPath);

            // Subject
            String subject = mimeMessage.getSubject();
            builder.subject(subject != null ? subject : "(No Subject)");

            // Date
            Date sentDate = mimeMessage.getSentDate();
            builder.date(sentDate != null ? sentDate.toInstant() : Instant.now());

            // From
            Address[] fromAddresses = mimeMessage.getFrom();
            if (fromAddresses != null && fromAddresses.length > 0) {
                Address primaryFrom = fromAddresses[0];
                builder.from(primaryFrom.toString());
                if (primaryFrom instanceof InternetAddress ia) {
                    builder.fromDisplayName(ia.getPersonal() != null ? ia.getPersonal() : "");
                    builder.fromAddress(ia.getAddress() != null ? ia.getAddress() : "");
                } else {
                    builder.fromAddress(cleanAddress(primaryFrom.toString()));
                }
            }

            // Reply-To
            Address[] replyTo = mimeMessage.getReplyTo();
            if (replyTo != null && replyTo.length > 0) {
                builder.replyTo(cleanAddress(replyTo[0].toString()));
            }

            // Recipients
            builder.to(extractAddressList(mimeMessage.getRecipients(Message.RecipientType.TO)));
            builder.cc(extractAddressList(mimeMessage.getRecipients(Message.RecipientType.CC)));
            builder.bcc(extractAddressList(mimeMessage.getRecipients(Message.RecipientType.BCC)));

            // Parse Body Content & Attachments recursively
            ParsedMimeContent parsedContent = new ParsedMimeContent();
            extractParts(mimeMessage, parsedContent);

            builder.bodyText(parsedContent.bodyText.toString().trim());
            builder.bodyHtml(parsedContent.bodyHtml.toString().trim());
            builder.attachments(parsedContent.attachments);

            // Parse Authentication-Results header
            AuthenticationResult authResult = parseAuthenticationResults(headerList);
            builder.authResult(authResult);

            // Extract URLs if UrlAnalyzer is present
            if (urlAnalyzer != null) {
                List<ExtractedUrl> urls = urlAnalyzer.extractUrls(parsedContent.bodyText.toString(), parsedContent.bodyHtml.toString());
                builder.extractedUrls(urls);
            }

            return builder.build();

        } catch (MessagingException | IOException e) {
            log.warn("Standard MIME parsing failed, attempting fallback header/body text parse: {}", e.getMessage());
            return fallbackParse(rawBytes, providerType);
        }
    }

    private void extractParts(Part part, ParsedMimeContent content) throws MessagingException, IOException {
        String disposition = part.getDisposition();
        String contentType = part.getContentType() != null ? part.getContentType().toLowerCase(Locale.ROOT) : "";

        // Check if part is an attachment
        boolean isAttachment = Part.ATTACHMENT.equalsIgnoreCase(disposition) ||
                (part.getFileName() != null && !part.getFileName().isBlank() && !contentType.startsWith("multipart/"));

        if (isAttachment) {
            String filename = part.getFileName();
            if (filename == null || filename.isBlank()) {
                filename = "attachment_" + (content.attachments.size() + 1);
            }
            long size = part.getSize() > 0 ? part.getSize() : 0;
            String hash = "";

            // Safely read attachment bytes to calculate SHA-256
            try (InputStream is = part.getInputStream()) {
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                byte[] buf = new byte[4096];
                int r;
                while ((r = is.read(buf)) != -1) {
                    baos.write(buf, 0, r);
                }
                byte[] attBytes = baos.toByteArray();
                size = attBytes.length;
                hash = SecurityUtils.sha256Hex(attBytes);
            } catch (Exception ignored) {}

            EmailAttachmentMetadata metadata = new EmailAttachmentMetadata(
                    filename,
                    part.getContentType(),
                    size,
                    hash,
                    false,
                    ""
            );
            content.attachments.add(metadata);
            return;
        }

        // Process MIME body parts
        if (part.isMimeType("text/plain")) {
            Object obj = part.getContent();
            if (obj != null) {
                content.bodyText.append(obj.toString()).append("\n");
            }
        } else if (part.isMimeType("text/html")) {
            Object obj = part.getContent();
            if (obj != null) {
                content.bodyHtml.append(obj.toString()).append("\n");
            }
        } else if (part.isMimeType("multipart/*")) {
            Object multi = part.getContent();
            if (multi instanceof Multipart mp) {
                for (int i = 0; i < mp.getCount(); i++) {
                    extractParts(mp.getBodyPart(i), content);
                }
            }
        } else if (part.isMimeType("message/rfc822")) {
            Object nested = part.getContent();
            if (nested instanceof Part nestedPart) {
                extractParts(nestedPart, content);
            }
        }
    }

    /**
     * Fallback parser for malformed emails or partial headers pasted without complete MIME boundaries.
     */
    private EmailMessage fallbackParse(byte[] rawBytes, ProviderType providerType) {
        String raw = new String(rawBytes, StandardCharsets.UTF_8);
        String[] lines = raw.split("\\r?\\n");

        EmailMessage.Builder builder = EmailMessage.builder();
        builder.providerSource(providerType);
        builder.rawBytes(rawBytes);
        builder.rawSha256(SecurityUtils.sha256Hex(rawBytes));

        List<EmailHeader> headers = new ArrayList<>();
        StringBuilder body = new StringBuilder();
        boolean inHeader = true;

        for (String line : lines) {
            if (inHeader) {
                if (line.isBlank()) {
                    inHeader = false;
                    continue;
                }
                int colonIdx = line.indexOf(':');
                if (colonIdx > 0) {
                    String name = line.substring(0, colonIdx).trim();
                    String value = line.substring(colonIdx + 1).trim();
                    headers.add(new EmailHeader(name, value, line));

                    if (name.equalsIgnoreCase("From")) {
                        builder.from(value);
                        builder.fromAddress(cleanAddress(value));
                    } else if (name.equalsIgnoreCase("Subject")) {
                        builder.subject(value);
                    } else if (name.equalsIgnoreCase("Reply-To")) {
                        builder.replyTo(cleanAddress(value));
                    } else if (name.equalsIgnoreCase("Return-Path")) {
                        builder.returnPath(cleanAddress(value));
                    } else if (name.equalsIgnoreCase("Message-ID")) {
                        builder.messageIdHeader(value);
                    }
                }
            } else {
                body.append(line).append("\n");
            }
        }

        builder.headers(headers);
        builder.bodyText(body.toString().trim());
        builder.authResult(parseAuthenticationResults(headers));

        if (urlAnalyzer != null) {
            List<ExtractedUrl> urls = urlAnalyzer.extractUrls(body.toString(), "");
            builder.extractedUrls(urls);
        }

        return builder.build();
    }

    public static AuthenticationResult parseAuthenticationResults(List<EmailHeader> headers) {
        String authHeaderValue = null;
        String receivedSpfValue = null;

        for (EmailHeader h : headers) {
            if (h.getName().equalsIgnoreCase("Authentication-Results")) {
                authHeaderValue = h.getValue();
            } else if (h.getName().equalsIgnoreCase("Received-SPF")) {
                receivedSpfValue = h.getValue();
            }
        }

        if (authHeaderValue == null && receivedSpfValue == null) {
            return AuthenticationResult.missing();
        }

        AuthenticationResult.AuthStatus spfStatus = AuthenticationResult.AuthStatus.UNKNOWN;
        String spfSender = "";
        AuthenticationResult.AuthStatus dkimStatus = AuthenticationResult.AuthStatus.UNKNOWN;
        String dkimDomain = "";
        AuthenticationResult.AuthStatus dmarcStatus = AuthenticationResult.AuthStatus.UNKNOWN;
        String dmarcPolicy = "";

        String combined = (authHeaderValue != null ? authHeaderValue : "") + " " + (receivedSpfValue != null ? receivedSpfValue : "");
        String lower = combined.toLowerCase(Locale.ROOT);

        // SPF check
        if (lower.contains("spf=pass") || lower.contains("spf: pass") || (receivedSpfValue != null && receivedSpfValue.toLowerCase().startsWith("pass"))) {
            spfStatus = AuthenticationResult.AuthStatus.PASS;
        } else if (lower.contains("spf=fail") || lower.contains("spf: fail") || (receivedSpfValue != null && receivedSpfValue.toLowerCase().startsWith("fail"))) {
            spfStatus = AuthenticationResult.AuthStatus.FAIL;
        } else if (lower.contains("spf=softfail") || (receivedSpfValue != null && receivedSpfValue.toLowerCase().startsWith("softfail"))) {
            spfStatus = AuthenticationResult.AuthStatus.SOFTFAIL;
        } else if (lower.contains("spf=neutral") || lower.contains("spf=none")) {
            spfStatus = AuthenticationResult.AuthStatus.NEUTRAL;
        }

        // DKIM check
        if (lower.contains("dkim=pass")) {
            dkimStatus = AuthenticationResult.AuthStatus.PASS;
        } else if (lower.contains("dkim=fail")) {
            dkimStatus = AuthenticationResult.AuthStatus.FAIL;
        } else if (lower.contains("dkim=none")) {
            dkimStatus = AuthenticationResult.AuthStatus.NONE;
        }

        // DMARC check
        if (lower.contains("dmarc=pass")) {
            dmarcStatus = AuthenticationResult.AuthStatus.PASS;
        } else if (lower.contains("dmarc=fail")) {
            dmarcStatus = AuthenticationResult.AuthStatus.FAIL;
        } else if (lower.contains("dmarc=none")) {
            dmarcStatus = AuthenticationResult.AuthStatus.NONE;
        }

        // Extract sender domain or dkim domain if present
        Pattern dkimPattern = Pattern.compile("header\\.d=([a-zA-Z0-9.-]+)");
        Matcher dkimMatcher = dkimPattern.matcher(combined);
        if (dkimMatcher.find()) {
            dkimDomain = dkimMatcher.group(1);
        }

        Pattern spfPattern = Pattern.compile("smtp\\.mailfrom=([a-zA-Z0-9.@_-]+)");
        Matcher spfMatcher = spfPattern.matcher(combined);
        if (spfMatcher.find()) {
            spfSender = spfMatcher.group(1);
        }

        return new AuthenticationResult(
                spfStatus,
                spfSender,
                dkimStatus,
                dkimDomain,
                dmarcStatus,
                dmarcPolicy,
                authHeaderValue != null ? authHeaderValue : receivedSpfValue,
                true
        );
    }

    private static String cleanAddress(String raw) {
        if (raw == null) return "";
        // If format is "Name <addr@domain.com>", extract addr@domain.com
        int start = raw.indexOf('<');
        int end = raw.indexOf('>');
        if (start >= 0 && end > start) {
            return raw.substring(start + 1, end).trim().toLowerCase(Locale.ROOT);
        }
        return raw.trim().toLowerCase(Locale.ROOT);
    }

    private static List<String> extractAddressList(Address[] addresses) {
        if (addresses == null) return Collections.emptyList();
        List<String> list = new ArrayList<>();
        for (Address a : addresses) {
            if (a instanceof InternetAddress ia && ia.getAddress() != null) {
                list.add(ia.getAddress().trim().toLowerCase(Locale.ROOT));
            } else {
                list.add(cleanAddress(a.toString()));
            }
        }
        return list;
    }

    private static class ParsedMimeContent {
        final StringBuilder bodyText = new StringBuilder();
        final StringBuilder bodyHtml = new StringBuilder();
        final List<EmailAttachmentMetadata> attachments = new ArrayList<>();
    }
}

