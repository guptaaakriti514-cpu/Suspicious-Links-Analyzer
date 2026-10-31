package com.mailshield.detection;

import com.mailshield.model.*;
import com.mailshield.util.SecurityUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Robust analyzer for RFC 5322 header anomalies, sender spoofing, display name tricks,
 * and authentication status parsing.
 */
public class SafeHeaderAnalyzer implements HeaderAnalyzer {

    @Override
    public List<Finding> analyzeHeaders(EmailMessage message) {
        List<Finding> findings = new ArrayList<>();

        String fromAddress = message.getFromAddress();
        String fromDisplayName = message.getFromDisplayName();
        String replyTo = message.getReplyTo();
        String returnPath = message.getReturnPath();
        String senderDomain = message.getSenderDomain();

        // 1. From vs Reply-To Mismatch
        if (!replyTo.isBlank() && !fromAddress.isBlank()) {
            String fromDomain = SecurityUtils.extractRegistrableDomain(senderDomain);
            String replyToDomain = SecurityUtils.extractRegistrableDomain(extractDomain(replyTo));

            if (!fromDomain.isBlank() && !replyToDomain.isBlank() && !fromDomain.equalsIgnoreCase(replyToDomain)) {
                // Check if reply-to is a free webmail service while from is a commercial brand
                boolean isFreeWebmail = replyTo.endsWith("@gmail.com") || replyTo.endsWith("@yahoo.com") ||
                                       replyTo.endsWith("@outlook.com") || replyTo.endsWith("@hotmail.com");

                Severity sev = isFreeWebmail ? Severity.HIGH : Severity.MEDIUM;
                findings.add(Finding.builder()
                        .ruleId("HDR-001")
                        .ruleVersion("1.0.0")
                        .category(FindingCategory.HEADER_ANOMALY)
                        .severity(sev)
                        .confidence(0.85)
                        .shortDescription("From and Reply-To Domain Inconsistency")
                        .explanation("The From domain differs from the Reply-To domain. Replies will be routed to an alternate organization or address.")
                        .evidenceSnippet(String.format("From: <%s> vs Reply-To: <%s>", fromAddress, replyTo))
                        .sourceLocation("RFC 5322 Headers: From / Reply-To")
                        .findingType(FindingType.HEURISTIC)
                        .safeNextStep("Ensure any replies are sent only to the authenticated sender domain, not an unverified external address.")
                        .build());
            }
        }

        // 2. Display Name Spoofing (Display Name contains an email address or known brand that differs from From address)
        if (!fromDisplayName.isBlank()) {
            String lowerName = fromDisplayName.toLowerCase(Locale.ROOT);
            // Check if display name impersonates an executive, security team, or known brand
            if ((lowerName.contains("paypal") || lowerName.contains("microsoft") ||
                 lowerName.contains("google") || lowerName.contains("it support") ||
                 lowerName.contains("security alert") || lowerName.contains("bank") ||
                 lowerName.contains("ceo") || lowerName.contains("executive")) &&
                !senderDomain.contains("paypal.com") && !senderDomain.contains("microsoft.com") &&
                !senderDomain.contains("google.com")) {

                findings.add(Finding.builder()
                        .ruleId("HDR-002")
                        .ruleVersion("1.0.0")
                        .category(FindingCategory.SPOOFING_IMPERSONATION)
                        .severity(Severity.HIGH)
                        .confidence(0.90)
                        .shortDescription("Display Name Brand / Authority Spoofing")
                        .explanation("The sender's display name implies a trusted organization or role, but the actual sending address is hosted on an unrelated external domain.")
                        .evidenceSnippet(String.format("Display Name: \"%s\" | Actual Address: <%s>", fromDisplayName, fromAddress))
                        .sourceLocation("Header: From")
                        .findingType(FindingType.HEURISTIC)
                        .safeNextStep("Never trust the sender name alone; verify the envelope domain carefully.")
                        .build());
            }

            // Check if display name contains an embedded email address to trick mobile clients
            if (fromDisplayName.contains("@") && !fromDisplayName.toLowerCase().contains(fromAddress)) {
                findings.add(Finding.builder()
                        .ruleId("HDR-003")
                        .ruleVersion("1.0.0")
                        .category(FindingCategory.SPOOFING_IMPERSONATION)
                        .severity(Severity.HIGH)
                        .confidence(0.88)
                        .shortDescription("Embedded Email Address in Display Name")
                        .explanation("The display name contains an email address that does not match the actual envelope From address (a mobile UI spoofing trick).")
                        .evidenceSnippet(String.format("Display: \"%s\" vs From: <%s>", fromDisplayName, fromAddress))
                        .sourceLocation("Header: From")
                        .findingType(FindingType.HEURISTIC)
                        .safeNextStep("Verify actual envelope sender address rather than displayed text.")
                        .build());
            }
        }

        // 3. Return-Path Mismatch (Heuristic, not definitive fraud)
        if (!returnPath.isBlank() && !fromAddress.isBlank()) {
            String fromDomain = SecurityUtils.extractRegistrableDomain(senderDomain);
            String returnDomain = SecurityUtils.extractRegistrableDomain(extractDomain(returnPath));
            if (!fromDomain.isBlank() && !returnDomain.isBlank() && !fromDomain.equalsIgnoreCase(returnDomain)) {
                findings.add(Finding.builder()
                        .ruleId("HDR-004")
                        .ruleVersion("1.0.0")
                        .category(FindingCategory.HEADER_ANOMALY)
                        .severity(Severity.LOW)
                        .confidence(0.55)
                        .shortDescription("Return-Path and From Domain Divergence")
                        .explanation("The Return-Path (bounce destination) domain differs from the From address. Often legitimate for mailing lists, but common in spam relays.")
                        .evidenceSnippet(String.format("Return-Path: <%s> vs From: <%s>", returnPath, fromAddress))
                        .sourceLocation("Header: Return-Path")
                        .findingType(FindingType.HEURISTIC)
                        .safeNextStep("Treat as a contextual indicator alongside SPF/DKIM verification.")
                        .build());
            }
        }

        // 4. Missing Message-ID
        if (message.getMessageIdHeader().isBlank()) {
            findings.add(Finding.builder()
                    .ruleId("HDR-005")
                    .ruleVersion("1.0.0")
                    .category(FindingCategory.HEADER_ANOMALY)
                    .severity(Severity.LOW)
                    .confidence(0.60)
                    .shortDescription("Missing RFC 5322 Message-ID Header")
                    .explanation("The email lacks a standard Message-ID header, which is standard for legitimate mail user agents and MTAs.")
                    .evidenceSnippet("Message-ID: (absent)")
                    .sourceLocation("RFC 5322 Envelope Headers")
                    .findingType(FindingType.METADATA_OBSERVATION)
                    .safeNextStep("Inspect MTA relay logs to confirm origin.")
                    .build());
        }

        // 5. Authentication Analysis (SPF, DKIM, DMARC)
        AuthenticationResult auth = message.getAuthResult();
        if (!auth.isHasAuthenticationHeader()) {
            findings.add(Finding.builder()
                    .ruleId("AUTH-001")
                    .ruleVersion("1.0.0")
                    .category(FindingCategory.AUTHENTICATION_FAILURE)
                    .severity(Severity.INFO)
                    .confidence(0.50)
                    .shortDescription("No Authentication-Results Header Found")
                    .explanation("The message lacks SPF/DKIM/DMARC authentication verdicts in its headers. This is common for local/exported .eml files or internal hops.")
                    .evidenceSnippet("Authentication-Results: (not present)")
                    .sourceLocation("Headers")
                    .findingType(FindingType.PARSED_AUTHENTICATION_EVIDENCE)
                    .safeNextStep("Authentication status is Unknown; do not assume the email is safe.")
                    .build());
        } else {
            // SPF
            if (auth.getSpfStatus() == AuthenticationResult.AuthStatus.FAIL) {
                findings.add(Finding.builder()
                        .ruleId("AUTH-002")
                        .ruleVersion("1.0.0")
                        .category(FindingCategory.AUTHENTICATION_FAILURE)
                        .severity(Severity.HIGH)
                        .confidence(0.92)
                        .shortDescription("SPF Authentication Failure (spf=fail)")
                        .explanation("The sending server IP address was not authorized by the sender's published DNS SPF record to transmit emails on its behalf.")
                        .evidenceSnippet("SPF Verdict: FAIL | Sender: " + auth.getSpfSender())
                        .sourceLocation("Authentication-Results: spf=fail")
                        .findingType(FindingType.PARSED_AUTHENTICATION_EVIDENCE)
                        .safeNextStep("High likelihood of sender spoofing or unauthorized relay usage.")
                        .build());
            } else if (auth.getSpfStatus() == AuthenticationResult.AuthStatus.SOFTFAIL) {
                findings.add(Finding.builder()
                        .ruleId("AUTH-003")
                        .ruleVersion("1.0.0")
                        .category(FindingCategory.AUTHENTICATION_FAILURE)
                        .severity(Severity.MEDIUM)
                        .confidence(0.75)
                        .shortDescription("SPF SoftFail (spf=softfail)")
                        .explanation("The sending host is not explicitly permitted under the sender domain's SPF record (~all).")
                        .evidenceSnippet("SPF Verdict: SOFTFAIL")
                        .sourceLocation("Authentication-Results: spf=softfail")
                        .findingType(FindingType.PARSED_AUTHENTICATION_EVIDENCE)
                        .safeNextStep("Examine transmitting MTA address.")
                        .build());
            }

            // DKIM
            if (auth.getDkimStatus() == AuthenticationResult.AuthStatus.FAIL) {
                findings.add(Finding.builder()
                        .ruleId("AUTH-004")
                        .ruleVersion("1.0.0")
                        .category(FindingCategory.AUTHENTICATION_FAILURE)
                        .severity(Severity.HIGH)
                        .confidence(0.90)
                        .shortDescription("DKIM Cryptographic Signature Failure (dkim=fail)")
                        .explanation("The message content or headers do not match the sender's cryptographic DKIM signature, indicating transmission tampering or signature invalidity.")
                        .evidenceSnippet("DKIM Verdict: FAIL | Domain: " + auth.getDkimDomain())
                        .sourceLocation("Authentication-Results: dkim=fail")
                        .findingType(FindingType.PARSED_AUTHENTICATION_EVIDENCE)
                        .safeNextStep("Do not trust the content integrity of this email.")
                        .build());
            }

            // DMARC
            if (auth.getDmarcStatus() == AuthenticationResult.AuthStatus.FAIL) {
                findings.add(Finding.builder()
                        .ruleId("AUTH-005")
                        .ruleVersion("1.0.0")
                        .category(FindingCategory.AUTHENTICATION_FAILURE)
                        .severity(Severity.HIGH)
                        .confidence(0.92)
                        .shortDescription("DMARC Policy Alignment Failure (dmarc=fail)")
                        .explanation("The message failed domain alignment requirements specified by the organization's published DMARC policy.")
                        .evidenceSnippet("DMARC Verdict: FAIL")
                        .sourceLocation("Authentication-Results: dmarc=fail")
                        .findingType(FindingType.PARSED_AUTHENTICATION_EVIDENCE)
                        .safeNextStep("Treat with heightened scrutiny as sender domain reject/quarantine policy was violated.")
                        .build());
            }
        }

        return findings;
    }

    private String extractDomain(String address) {
        if (address == null || !address.contains("@")) return "";
        return address.substring(address.lastIndexOf('@') + 1).trim().toLowerCase(Locale.ROOT);
    }
}

