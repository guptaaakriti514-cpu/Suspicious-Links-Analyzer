package com.mailshield.detection;

import com.mailshield.model.*;
import com.mailshield.util.SecurityUtils;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.net.URI;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Robust, secure URL extractor and analyzer.
 * Extracts links safely from plain text and HTML DOM, detects deceptive anchor mismatches,
 * IP hostnames, homoglyphs/punycode, user-info obfuscation, and URL shorteners.
 * NEVER follows redirects or makes outbound network calls during inspection.
 */
public class SafeUrlAnalyzer implements UrlAnalyzer {

    private static final Pattern PLAIN_TEXT_URL_PATTERN = Pattern.compile(
            "\\b(?:https?|ftp)://[-a-zA-Z0-9+&@#/%?=~_|!:,.;]*[-a-zA-Z0-9+&@#/%=~_|]",
            Pattern.CASE_INSENSITIVE
    );

    private static final Pattern IP_V4_PATTERN = Pattern.compile(
            "^(\\d{1,3}\\.){3}\\d{1,3}$"
    );

    private static final Set<String> KNOWN_SHORTENERS = Set.of(
            "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly",
            "rebrand.ly", "cutt.ly", "shorte.st", "goo.gl", "adf.ly"
    );

    private static final Set<String> HIGH_RISK_TLDS = Set.of(
            "top", "xyz", "click", "buzz", "work", "loan", "tk", "ml", "ga", "cf", "gq", "rest", "support"
    );

    // Well-known brands commonly targeted for typosquatting/homographs
    private static final Map<String, List<String>> BRAND_TYPOSQUATS = Map.of(
            "paypal", List.of("paypa1", "paypai", "pay-pal", "paypal-security", "paypal-update"),
            "microsoft", List.of("micros0ft", "m1crosoft", "micro-soft", "microsoft-verify"),
            "google", List.of("g00gle", "go0gle", "google-security", "google-account"),
            "apple", List.of("app1e", "apple-id-verify", "apple-support"),
            "amazon", List.of("amaz0n", "amazon-delivery", "amazon-order-security"),
            "netflix", List.of("netf1ix", "netflix-billing", "netflix-update")
    );

    @Override
    public List<ExtractedUrl> extractUrls(String bodyText, String bodyHtml) {
        Map<String, ExtractedUrl> urlMap = new LinkedHashMap<>();

        // 1. Extract from HTML DOM with anchor texts
        if (bodyHtml != null && !bodyHtml.isBlank()) {
            try {
                Document doc = Jsoup.parse(bodyHtml);
                Elements links = doc.select("a[href]");
                for (Element link : links) {
                    String href = link.attr("href").trim();
                    String anchorText = link.text().trim();
                    if (!href.isBlank() && (href.startsWith("http://") || href.startsWith("https://"))) {
                        ExtractedUrl inspected = inspectUrl(href, anchorText);
                        urlMap.put(inspected.getNormalizedUrl(), inspected);
                    }
                }
            } catch (Exception ignored) {}
        }

        // 2. Extract from plain text (or fall back if not found in HTML)
        if (bodyText != null && !bodyText.isBlank()) {
            Matcher matcher = PLAIN_TEXT_URL_PATTERN.matcher(bodyText);
            while (matcher.find()) {
                String matchedUrl = matcher.group();
                if (!urlMap.containsKey(matchedUrl.toLowerCase())) {
                    ExtractedUrl inspected = inspectUrl(matchedUrl, "");
                    urlMap.put(inspected.getNormalizedUrl(), inspected);
                }
            }
        }

        return new ArrayList<>(urlMap.values());
    }

    public ExtractedUrl inspectUrl(String rawUrl, String anchorText) {
        if (rawUrl == null || rawUrl.isBlank()) {
            return new ExtractedUrl("", "", "", "", "http", "", false, false, false, false, false, false, Collections.emptyList());
        }

        String scheme = "http";
        String domain = "";
        String path = "";
        boolean isShortened = false;
        boolean isIpHost = false;
        boolean hasHomograph = false;
        boolean isPunycode = false;
        boolean hasUserInfo = false;
        boolean isMismatchWithAnchor = false;
        List<String> reasons = new ArrayList<>();

        try {
            URI uri = URI.create(rawUrl.trim());
            scheme = uri.getScheme() != null ? uri.getScheme().toLowerCase() : "http";
            String host = uri.getHost();
            path = uri.getPath() != null ? uri.getPath() : "";

            if (uri.getUserInfo() != null && !uri.getUserInfo().isBlank()) {
                hasUserInfo = true;
                reasons.add("URL contains embedded user-info field: " + uri.getUserInfo() + " (often used to obscure destination)");
            }

            if (host != null && !host.isBlank()) {
                domain = host.toLowerCase().trim();

                // IP Address Host Check
                if (IP_V4_PATTERN.matcher(domain).matches()) {
                    isIpHost = true;
                    reasons.add("Destination host is a bare numerical IP address (" + domain + ") instead of a reputable domain name.");
                }

                // Punycode / Homograph Check
                if (domain.startsWith("xn--") || domain.contains(".xn--")) {
                    isPunycode = true;
                    hasHomograph = true;
                    reasons.add("Internationalized Domain Name (Punycode): " + domain + " (potential visual homograph deception).");
                }

                // URL Shortener Check
                String rootDomain = SecurityUtils.extractRegistrableDomain(domain);
                if (KNOWN_SHORTENERS.contains(rootDomain) || KNOWN_SHORTENERS.contains(domain)) {
                    isShortened = true;
                    reasons.add("URL uses link shortener service (" + domain + ") which conceals final destination.");
                }

                // Brand Typosquatting / Lookalike Check
                for (Map.Entry<String, List<String>> brandEntry : BRAND_TYPOSQUATS.entrySet()) {
                    String brand = brandEntry.getKey();
                    for (String typo : brandEntry.getValue()) {
                        if (domain.contains(typo) && !domain.endsWith("." + brand + ".com") && !domain.equals(brand + ".com")) {
                            hasHomograph = true;
                            reasons.add("Domain '" + domain + "' matches known deceptive typosquat pattern for brand: '" + brand + "'.");
                        }
                    }
                }

                // High-Risk TLD Check
                int lastDot = domain.lastIndexOf('.');
                if (lastDot > 0 && lastDot < domain.length() - 1) {
                    String tld = domain.substring(lastDot + 1);
                    if (HIGH_RISK_TLDS.contains(tld)) {
                        reasons.add("Domain uses high-abuse top-level domain (." + tld + ").");
                    }
                }
            }

            // Check anchor text mismatch: anchor text displays a URL that points to a different domain
            if (anchorText != null && !anchorText.isBlank()) {
                String cleanAnchor = anchorText.trim().toLowerCase();
                if (cleanAnchor.startsWith("http://") || cleanAnchor.startsWith("https://") || cleanAnchor.startsWith("www.")) {
                    try {
                        String anchorHost = cleanAnchor;
                        if (anchorHost.startsWith("http://") || anchorHost.startsWith("https://")) {
                            anchorHost = URI.create(cleanAnchor).getHost();
                        } else if (anchorHost.startsWith("www.")) {
                            int slash = anchorHost.indexOf('/');
                            anchorHost = slash > 0 ? anchorHost.substring(0, slash) : anchorHost;
                        }
                        if (anchorHost != null && host != null && !anchorHost.equalsIgnoreCase(host)) {
                            String anchorRoot = SecurityUtils.extractRegistrableDomain(anchorHost);
                            String actualRoot = SecurityUtils.extractRegistrableDomain(host);
                            if (!anchorRoot.equalsIgnoreCase(actualRoot)) {
                                isMismatchWithAnchor = true;
                                reasons.add(String.format("Deceptive link text: Visible text displays '%s' but destination points to '%s'.", anchorHost, host));
                            }
                        }
                    } catch (Exception ignored) {}
                }
            }

        } catch (Exception e) {
            reasons.add("Malformed URL syntax: " + e.getMessage());
        }

        return new ExtractedUrl(
                rawUrl,
                rawUrl.toLowerCase(),
                domain,
                path,
                scheme,
                anchorText,
                isShortened,
                isIpHost,
                hasHomograph,
                isPunycode,
                hasUserInfo,
                isMismatchWithAnchor,
                reasons
        );
    }

    @Override
    public List<Finding> analyzeUrls(EmailMessage message) {
        List<Finding> findings = new ArrayList<>();
        List<ExtractedUrl> urls = message.getExtractedUrls();

        if (urls == null || urls.isEmpty()) {
            return findings;
        }

        for (ExtractedUrl u : urls) {
            // Finding: Anchor Text Deception
            if (u.isMismatchWithAnchor()) {
                findings.add(Finding.builder()
                        .ruleId("URL-001")
                        .ruleVersion("1.0.0")
                        .category(FindingCategory.SUSPICIOUS_URL)
                        .severity(Severity.CRITICAL)
                        .confidence(0.95)
                        .shortDescription("Deceptive Anchor Text Mismatch")
                        .explanation("The visible link text depicts a reputable service, but the actual hyperlink routes user traffic to a different external host.")
                        .evidenceSnippet(String.format("Text: '%s' -> Destination: '%s'", u.getAnchorText(), u.getOriginalUrl()))
                        .sourceLocation("HTML Link: " + u.getOriginalUrl())
                        .findingType(FindingType.HEURISTIC)
                        .safeNextStep("Do NOT click this link. It is an intentional misdirection typical of credential phishing.")
                        .build());
            }

            // Finding: IP Address Host Destination
            if (u.isIpHost()) {
                findings.add(Finding.builder()
                        .ruleId("URL-002")
                        .ruleVersion("1.0.0")
                        .category(FindingCategory.SUSPICIOUS_URL)
                        .severity(Severity.HIGH)
                        .confidence(0.90)
                        .shortDescription("Bare IP Hostname Destination")
                        .explanation("The hyperlink destination uses a raw IP address instead of a registered domain name, often to bypass domain reputation blocklists.")
                        .evidenceSnippet("Host: " + u.getDomain())
                        .sourceLocation("Hyperlink Target: " + u.getOriginalUrl())
                        .findingType(FindingType.HEURISTIC)
                        .safeNextStep("Inspect network origin and block access to unverified external IP.")
                        .build());
            }

            // Finding: Homoglyph or Typosquat Domain
            if (u.hasHomograph() || u.isPunycode()) {
                findings.add(Finding.builder()
                        .ruleId("URL-003")
                        .ruleVersion("1.0.0")
                        .category(FindingCategory.SUSPICIOUS_URL)
                        .severity(Severity.HIGH)
                        .confidence(0.85)
                        .shortDescription("Typosquat / Homograph Domain Detected")
                        .explanation("The domain in this URL appears to mimic a known brand or uses Punycode internationalization to deceive the user.")
                        .evidenceSnippet("Domain: " + u.getDomain())
                        .sourceLocation("URL Domain: " + u.getOriginalUrl())
                        .findingType(FindingType.HEURISTIC)
                        .safeNextStep("Compare domain spelling against the official legitimate website.")
                        .build());
            }

            // Finding: Embedded User-Info
            if (u.hasUserInfo()) {
                findings.add(Finding.builder()
                        .ruleId("URL-004")
                        .ruleVersion("1.0.0")
                        .category(FindingCategory.SUSPICIOUS_URL)
                        .severity(Severity.HIGH)
                        .confidence(0.85)
                        .shortDescription("Obfuscated User-Info in URL")
                        .explanation("The URL uses the user-info '@' prefix syntax, which causes browsers to navigate to the host following '@' rather than the misleading prefix.")
                        .evidenceSnippet("URL: " + u.getOriginalUrl())
                        .sourceLocation("URL User-Info")
                        .findingType(FindingType.HEURISTIC)
                        .safeNextStep("Disregard domain prior to '@' and examine destination host.")
                        .build());
            }

            // Finding: Shortened URL
            if (u.isShortened()) {
                findings.add(Finding.builder()
                        .ruleId("URL-005")
                        .ruleVersion("1.0.0")
                        .category(FindingCategory.SUSPICIOUS_URL)
                        .severity(Severity.MEDIUM)
                        .confidence(0.70)
                        .shortDescription("URL Shortener Concealing Final Destination")
                        .explanation("The email uses a link redirection/shortening service that conceals the true landing page from security scanners and users.")
                        .evidenceSnippet("Shortener: " + u.getDomain())
                        .sourceLocation("Hyperlink: " + u.getOriginalUrl())
                        .findingType(FindingType.HEURISTIC)
                        .safeNextStep("Expand the shortened URL using a dedicated security sandbox if necessary.")
                        .build());
            }

            // Finding: Insecure HTTP Protocol for Sensitive Actions
            if ("http".equalsIgnoreCase(u.getScheme()) && !u.isIpHost()) {
                findings.add(Finding.builder()
                        .ruleId("URL-006")
                        .ruleVersion("1.0.0")
                        .category(FindingCategory.SUSPICIOUS_URL)
                        .severity(Severity.LOW)
                        .confidence(0.60)
                        .shortDescription("Unencrypted HTTP Link")
                        .explanation("The hyperlink uses unencrypted HTTP rather than HTTPS.")
                        .evidenceSnippet("Scheme: http:// -> " + u.getDomain())
                        .sourceLocation("URL Scheme")
                        .findingType(FindingType.METADATA_OBSERVATION)
                        .safeNextStep("Note: Lack of HTTPS indicates insecure communication; however, HTTPS alone does not guarantee safety.")
                        .build());
            }
        }

        return findings;
    }
}

