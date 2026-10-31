package com.mailshield.detection;

import com.mailshield.model.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Context-aware content and social engineering analyzer.
 * Identifies high-urgency deadlines, account suspension threats, financial extortion/wire demands,
 * and credential solicitation without relying on single isolated words.
 */
public class SafeContentAnalyzer implements ContentAnalyzer {

    // Context-aware compound patterns (Requiring semantic pairing, e.g. "within 24 hours" + "suspended" or "wire transfer" + "confidential")
    private static final Pattern URGENT_DEADLINE_PATTERN = Pattern.compile(
            "\\b(within\\s+(?:24|48|12)\\s*hours?|immediately|without\\s+delay|urgent(?:ly)?|asap|time[ -]sensitive|action\\s+required)\\b",
            Pattern.CASE_INSENSITIVE
    );

    private static final Pattern ACCOUNT_SUSPENSION_PATTERN = Pattern.compile(
            "\\b(account\\s+(?:will\\s+be\\s+)?(?:suspended|terminated|disabled|locked|restricted|frozen|closed)|unauthorized\\s+(?:access|sign-in|activity)|suspicious\\s+(?:login|activity))\\b",
            Pattern.CASE_INSENSITIVE
    );

    private static final Pattern CREDENTIAL_HARVEST_PATTERN = Pattern.compile(
            "\\b(verify\\s+your\\s+(?:identity|account|credentials|password)|update\\s+your\\s+(?:billing|password|security\\s+details)|log\\s*in\\s+to\\s+(?:verify|reactivate|unlock)|confirm\\s+your\\s+(?:password|pin|ssn|social\\s+security))\\b",
            Pattern.CASE_INSENSITIVE
    );

    private static final Pattern WIRE_FRAUD_BEC_PATTERN = Pattern.compile(
            "\\b(wire\\s+transfer|wire\\s+funds|urgent\\s+payment|remittance\\s+advice|escrow\\s+account|bank\\s+coordinates|outbound\\s+transfer|strictly\\s+confidential)\\b",
            Pattern.CASE_INSENSITIVE
    );

    private static final Pattern EXECUTIVE_PRESSURE_PATTERN = Pattern.compile(
            "\\b(in\\s+a\\s+meeting|cannot\\s+take\\s+(?:calls|voice\\s+calls)|do\\s+not\\s+discuss\\s+with|nda\\s+strictly\\s+enforced|confidential\\s+acquisition|executive\\s+directive)\\b",
            Pattern.CASE_INSENSITIVE
    );

    private static final Pattern EXTORTION_BLACKMAIL_PATTERN = Pattern.compile(
            "\\b(bitcoin|btc|wallet\\s+address|compromised\\s+your\\s+webcam|recorded\\s+video|ransom|pay\\s+within)\\b",
            Pattern.CASE_INSENSITIVE
    );

    @Override
    public List<Finding> analyzeContent(EmailMessage message) {
        List<Finding> findings = new ArrayList<>();
        String combinedContent = (message.getSubject() + " " + message.getBodyText()).toLowerCase(Locale.ROOT);

        if (combinedContent.isBlank()) {
            return findings;
        }

        boolean hasUrgency = URGENT_DEADLINE_PATTERN.matcher(combinedContent).find();
        boolean hasSuspension = ACCOUNT_SUSPENSION_PATTERN.matcher(combinedContent).find();
        boolean hasCredentialHarvest = CREDENTIAL_HARVEST_PATTERN.matcher(combinedContent).find();
        boolean hasWireDemand = WIRE_FRAUD_BEC_PATTERN.matcher(combinedContent).find();
        boolean hasExecutivePressure = EXECUTIVE_PRESSURE_PATTERN.matcher(combinedContent).find();
        boolean hasExtortion = EXTORTION_BLACKMAIL_PATTERN.matcher(combinedContent).find();

        // 1. Phishing Lure: Urgency + Account Suspension / Termination Threat
        if (hasUrgency && hasSuspension) {
            findings.add(Finding.builder()
                    .ruleId("SOC-001")
                    .ruleVersion("1.0.0")
                    .category(FindingCategory.SOCIAL_ENGINEERING)
                    .severity(Severity.HIGH)
                    .confidence(0.90)
                    .shortDescription("High-Urgency Account Suspension Threat")
                    .explanation("The email combines an artificial deadline with threats of immediate account termination, a hallmark psychological pressure tactic in phishing.")
                    .evidenceSnippet(extractSnippet(combinedContent, ACCOUNT_SUSPENSION_PATTERN))
                    .sourceLocation("Subject / Body Content")
                    .findingType(FindingType.HEURISTIC)
                    .safeNextStep("Never follow panic links. Log into the provider's official portal directly in a clean browser window.")
                    .build());
        }

        // 2. Credential Solicitation
        if (hasCredentialHarvest) {
            findings.add(Finding.builder()
                    .ruleId("SOC-002")
                    .ruleVersion("1.0.0")
                    .category(FindingCategory.SOCIAL_ENGINEERING)
                    .severity(Severity.HIGH)
                    .confidence(0.88)
                    .shortDescription("Direct Credential or Identity Solicitation")
                    .explanation("The message instructs the recipient to verify or input login credentials, security pins, or identity records.")
                    .evidenceSnippet(extractSnippet(combinedContent, CREDENTIAL_HARVEST_PATTERN))
                    .sourceLocation("Body Content")
                    .findingType(FindingType.HEURISTIC)
                    .safeNextStep("Legitimate security teams rarely request password updates via unsolicited email links.")
                    .build());
        }

        // 3. Business Email Compromise (BEC) / CEO Fraud Wire Request
        if (hasWireDemand && (hasExecutivePressure || hasUrgency)) {
            findings.add(Finding.builder()
                    .ruleId("SOC-003")
                    .ruleVersion("1.0.0")
                    .category(FindingCategory.SOCIAL_ENGINEERING)
                    .severity(Severity.CRITICAL)
                    .confidence(0.92)
                    .shortDescription("Business Email Compromise (BEC) Wire Transfer Lure")
                    .explanation("The email requests an urgent or confidential financial wire transaction while invoking executive secrecy or unavailable voice channels.")
                    .evidenceSnippet(extractSnippet(combinedContent, WIRE_FRAUD_BEC_PATTERN))
                    .sourceLocation("Email Body")
                    .findingType(FindingType.HEURISTIC)
                    .safeNextStep("Mandate out-of-band verbal authorization with the sender using known internal contact information before processing any payment.")
                    .build());
        }

        // 4. Extortion / Blackmail Scam
        if (hasExtortion && hasUrgency) {
            findings.add(Finding.builder()
                    .ruleId("SOC-004")
                    .ruleVersion("1.0.0")
                    .category(FindingCategory.SOCIAL_ENGINEERING)
                    .severity(Severity.HIGH)
                    .confidence(0.90)
                    .shortDescription("Cryptocurrency Extortion / Blackmail Threat")
                    .explanation("The message alleges compromise of personal webcam/data and demands cryptocurrency payment under threat of disclosure.")
                    .evidenceSnippet(extractSnippet(combinedContent, EXTORTION_BLACKMAIL_PATTERN))
                    .sourceLocation("Email Body")
                    .findingType(FindingType.HEURISTIC)
                    .safeNextStep("These are standard mass-extortion spam campaigns. Do not respond or send payments.")
                    .build());
        }

        return findings;
    }

    private String extractSnippet(String content, Pattern pattern) {
        Matcher m = pattern.matcher(content);
        if (m.find()) {
            int start = Math.max(0, m.start() - 20);
            int end = Math.min(content.length(), m.end() + 20);
            return "..." + content.substring(start, end).replace("\n", " ").trim() + "...";
        }
        return "Pattern matched in text.";
    }
}

