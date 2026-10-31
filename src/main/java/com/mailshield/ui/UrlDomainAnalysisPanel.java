package com.mailshield.ui;

import com.mailshield.detection.SafeUrlAnalyzer;
import com.mailshield.intelligence.ThreatIntelligenceService;
import com.mailshield.model.ExtractedUrl;
import com.mailshield.model.Finding;
import com.mailshield.util.SecurityUtils;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.util.List;

/**
 * Screen 5: Standalone URL & Domain Forensics Inspector.
 * Allows analysts to paste any suspicious link, anchor text, or domain for deep static inspection
 * without ever executing network requests or following redirects.
 */
public class UrlDomainAnalysisPanel extends JPanel {

    private final SafeUrlAnalyzer urlAnalyzer = new SafeUrlAnalyzer();
    private final ThreatIntelligenceService threatIntelService;

    private JTextField txtUrlInput;
    private JTextField txtAnchorInput;
    private JTextArea txtResultsArea;

    public UrlDomainAnalysisPanel(ThreatIntelligenceService threatIntelService) {
        this.threatIntelService = threatIntelService;

        setLayout(new BorderLayout(16, 16));
        setBackground(UiTheme.BG_DARK);
        setBorder(new EmptyBorder(16, 20, 16, 20));

        initHeader();
        initContent();
    }

    private void initHeader() {
        JPanel header = new JPanel(new GridLayout(2, 1, 0, 4));
        header.setOpaque(false);

        JLabel title = new JLabel("URL, Domain & Anchor Forensics Inspector");
        title.setFont(UiTheme.FONT_TITLE);

        JLabel subtitle = new JLabel("Evaluate deceptive anchor mismatches, numerical IP destinations, typosquats, and Punycode homoglyphs");
        subtitle.setFont(UiTheme.FONT_SMALL);
        subtitle.setForeground(UiTheme.TEXT_MUTED);

        header.add(title);
        header.add(subtitle);
        add(header, BorderLayout.NORTH);
    }

    private void initContent() {
        JPanel center = new JPanel(new BorderLayout(0, 16));
        center.setOpaque(false);

        // Input Card
        JPanel inputCard = UiTheme.createCardPanel();
        inputCard.setLayout(new GridLayout(3, 1, 0, 8));

        JPanel urlRow = new JPanel(new BorderLayout(8, 0));
        urlRow.setOpaque(false);
        JLabel lblUrl = new JLabel("Target URL / Domain: ");
        lblUrl.setFont(UiTheme.FONT_BOLD);
        txtUrlInput = new JTextField();
        txtUrlInput.setFont(UiTheme.FONT_MONO);
        urlRow.add(lblUrl, BorderLayout.WEST);
        urlRow.add(txtUrlInput, BorderLayout.CENTER);

        JPanel anchorRow = new JPanel(new BorderLayout(8, 0));
        anchorRow.setOpaque(false);
        JLabel lblAnchor = new JLabel("Visible Anchor Text:   ");
        lblAnchor.setFont(UiTheme.FONT_BOLD);
        txtAnchorInput = new JTextField();
        txtAnchorInput.setFont(UiTheme.FONT_MONO);
        txtAnchorInput.putClientProperty("JTextField.placeholderText", "Optional: Enter the visible clickable link text (to check anchor deception)");
        anchorRow.add(lblAnchor, BorderLayout.WEST);
        anchorRow.add(txtAnchorInput, BorderLayout.CENTER);

        JPanel btnRow = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));
        btnRow.setOpaque(false);

        JButton btnInspect = UiTheme.createStyledButton("Inspect URL Security", UiTheme.ACCENT_BLUE);
        btnInspect.addActionListener(e -> inspectUrl());

        JButton btnSamplePhish = UiTheme.createStyledButton("Load Sample Phishing Link", UiTheme.CARD_BG);
        btnSamplePhish.setBorder(BorderFactory.createLineBorder(UiTheme.BORDER_COLOR, 1));
        btnSamplePhish.addActionListener(e -> {
            txtUrlInput.setText("http://198.51.100.55/login/paypal-verification.php");
            txtAnchorInput.setText("https://www.paypal.com/signin/security");
            inspectUrl();
        });

        btnRow.add(btnSamplePhish);
        btnRow.add(btnInspect);

        inputCard.add(urlRow);
        inputCard.add(anchorRow);
        inputCard.add(btnRow);
        center.add(inputCard, BorderLayout.NORTH);

        // Output Card
        JPanel outputCard = UiTheme.createCardPanel();
        outputCard.setLayout(new BorderLayout(0, 10));

        JLabel outTitle = new JLabel("Forensics & Threat Indicator Verdict");
        outTitle.setFont(UiTheme.FONT_HEADER);
        outputCard.add(outTitle, BorderLayout.NORTH);

        txtResultsArea = new JTextArea("Enter a URL and click 'Inspect URL Security' to view static indicator breakdown.");
        txtResultsArea.setFont(UiTheme.FONT_MONO);
        txtResultsArea.setEditable(false);
        txtResultsArea.setBackground(UiTheme.CARD_BG);
        txtResultsArea.setLineWrap(true);
        txtResultsArea.setWrapStyleWord(true);

        JScrollPane scrollPane = new JScrollPane(txtResultsArea);
        scrollPane.setBorder(BorderFactory.createLineBorder(UiTheme.BORDER_COLOR, 1));
        outputCard.add(scrollPane, BorderLayout.CENTER);

        center.add(outputCard, BorderLayout.CENTER);
        add(center, BorderLayout.CENTER);
    }

    private void inspectUrl() {
        String url = txtUrlInput.getText().trim();
        String anchor = txtAnchorInput.getText().trim();

        if (url.isBlank()) {
            JOptionPane.showMessageDialog(this, "Please enter a target URL or domain to inspect.", "Input Required", JOptionPane.WARNING_MESSAGE);
            return;
        }

        ExtractedUrl inspected = urlAnalyzer.inspectUrl(url, anchor);

        StringBuilder sb = new StringBuilder();
        sb.append("========================================================================================\n");
        sb.append("MAILSHIELD URL & DOMAIN FORENSICS BREAKDOWN\n");
        sb.append("========================================================================================\n\n");
        sb.append(String.format("Destination URL:     %s\n", inspected.getOriginalUrl()));
        sb.append(String.format("Normalized URL:      %s\n", inspected.getNormalizedUrl()));
        sb.append(String.format("Target Domain:       %s\n", inspected.getDomain()));
        sb.append(String.format("Root Domain:         %s\n", SecurityUtils.extractRegistrableDomain(inspected.getDomain())));
        sb.append(String.format("URI Scheme:          %s\n", inspected.getScheme().toUpperCase()));
        sb.append(String.format("Visible Anchor Text: %s\n\n", inspected.getAnchorText().isBlank() ? "(None specified)" : inspected.getAnchorText()));

        sb.append("--- STATIC INDICATOR AUDIT ---\n");
        sb.append(String.format("• Bare IP Hostname:             %s\n", inspected.isIpHost() ? "[ALERT] YES (Suspicious IP destination)" : "[PASS] No"));
        sb.append(String.format("• Anchor Text Mismatch:         %s\n", inspected.isMismatchWithAnchor() ? "[CRITICAL] YES (Deceptive mismatch between text and target)" : "[PASS] No"));
        sb.append(String.format("• Homograph / Typosquatting:    %s\n", inspected.hasHomograph() ? "[ALERT] YES (Matches brand lookalike pattern)" : "[PASS] No"));
        sb.append(String.format("• URL Shortener:                %s\n", inspected.isShortened() ? "[WARN] YES (Destination masked by shortener service)" : "[PASS] No"));
        sb.append(String.format("• Obfuscated User-Info (@):     %s\n", inspected.hasUserInfo() ? "[WARN] YES (Contains embedded @ character)" : "[PASS] No"));
        sb.append(String.format("• Internationalized (Punycode): %s\n\n", inspected.isPunycode() ? "[WARN] YES (Punycode domain)" : "[PASS] No"));

        // Threat intelligence check
        if (threatIntelService != null) {
            sb.append("--- THREAT INTELLIGENCE REPUTATION ---\n");
            List<Finding> intel = threatIntelService.checkUrlReputation(inspected.getNormalizedUrl());
            if (intel.isEmpty()) {
                intel = threatIntelService.checkDomainReputation(inspected.getDomain());
            }
            if (!intel.isEmpty()) {
                for (Finding f : intel) {
                    sb.append(String.format("• [THREAT FEED HIT] %s: %s\n", f.getShortDescription(), f.getExplanation()));
                }
            } else {
                sb.append("• No active blacklists or reputation flags matched in current threat feed.\n");
            }
            sb.append("\n");
        }

        sb.append("--- ANALYST RECOMMENDATION ---\n");
        if (inspected.isMismatchWithAnchor() || inspected.isIpHost() || inspected.hasHomograph()) {
            sb.append(">>> VERDICT: MALICIOUS / HIGH-RISK CREDENTIAL PHISHING <<<\n");
            sb.append("Recommendation: Do NOT click this hyperlink. Block domain at enterprise DNS and boundary proxies.\n");
        } else {
            sb.append(">>> VERDICT: NO CRITICAL PHISHING HEURISTICS TRIGGERED <<<\n");
            sb.append("Recommendation: Standard precaution recommended. Verify domain authenticity out-of-band if unsolicited.\n");
        }

        txtResultsArea.setText(sb.toString());
    }
}

