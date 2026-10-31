package com.mailshield.ui;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;

/**
 * Screen 10: Academic Architecture, Viva Preparation & System Documentation.
 */
public class AboutHelpPanel extends JPanel {

    public AboutHelpPanel() {
        setLayout(new BorderLayout(16, 16));
        setBackground(UiTheme.BG_DARK);
        setBorder(new EmptyBorder(16, 20, 16, 20));

        initHeader();
        initContent();
    }

    private void initHeader() {
        JPanel header = new JPanel(new GridLayout(2, 1, 0, 4));
        header.setOpaque(false);

        JLabel title = new JLabel("MailShield &mdash; Academic Documentation & Viva Defense Guide");
        title.setFont(UiTheme.FONT_TITLE);

        JLabel subtitle = new JLabel("MCA Cybersecurity Academic Final Project: Architecture, Threat Modeling, and Examiner Q&A");
        subtitle.setFont(UiTheme.FONT_SMALL);
        subtitle.setForeground(UiTheme.TEXT_MUTED);

        header.add(title);
        header.add(subtitle);
        add(header, BorderLayout.NORTH);
    }

    private void initContent() {
        JPanel card = UiTheme.createCardPanel();
        card.setLayout(new BorderLayout());

        JEditorPane editorPane = new JEditorPane();
        editorPane.setContentType("text/html");
        editorPane.setEditable(false);
        editorPane.setBackground(UiTheme.CARD_BG);

        String html = """
            <html>
            <body style='font-family: Segoe UI, sans-serif; color: #f8fafc; background-color: #1e293b; padding: 12px; font-size: 11pt;'>
                <h2 style='color: #38bdf8;'>1. Project Overview & Scope</h2>
                <p><strong>MailShield</strong> is a specialized cybersecurity desktop platform engineered for Security Operations Center (SOC) analysts and digital forensics investigators. It bridges the gap between raw RFC 5322 email transmission protocols and explainable indicator triage.</p>

                <h2 style='color: #38bdf8;'>2. Core Layered Architecture</h2>
                <ul>
                    <li><strong>Ingestion Layer:</strong> Safe MIME recursion via Jakarta Mail 2.1, streaming RFC 5322 parser, base64 payload isolation.</li>
                    <li><strong>Detection Pipeline:</strong> 5 independent heuristic and evidentiary analyzers:
                        <ul>
                            <li><code>HeaderAnalyzer</code>: From vs Reply-To divergence, display-name spoofing, Return-Path heuristics.</li>
                            <li><code>ContentAnalyzer</code>: Compound social engineering patterns (urgency + account suspension, BEC wire lures).</li>
                            <li><code>UrlAnalyzer</code>: Deceptive anchor text mismatches, numerical IP hosts, homoglyphs/Punycode, shorteners.</li>
                            <li><code>AttachmentAnalyzer</code>: Disguised double extensions (.pdf.exe), macro formats (.docm), disk images (.iso).</li>
                            <li><code>AuthenticationAnalyzer</code>: Header-extracted SPF, DKIM, and DMARC verdicts.</li>
                        </ul>
                    </li>
                    <li><strong>Scoring Engine:</strong> Deterministic category ceiling caps preventing indicator multi-counting and inflation.</li>
                    <li><strong>Forensics & Storage:</strong> Immediate SHA-256 computation over raw message bytes, ACID SQLite repository.</li>
                    <li><strong>Reporting:</strong> Strict HTML entity escaping, SOC printable reporting, and CSV telemetry exports.</li>
                </ul>

                <h2 style='color: #38bdf8;'>3. Academic Viva Questions & Model Answers</h2>
                <p><strong>Q1: Why does MailShield evaluate SPF, DKIM, and DMARC from headers rather than performing DNS lookups directly?</strong><br/>
                <em>Answer:</em> Historical and imported .eml files must be audited as they were received at the time of transmission. Performing live DNS queries on an investigation workstation would evaluate the attacker's current DNS state, not the state when the incident occurred, introducing historical inaccuracy.</p>

                <p><strong>Q2: How does the system prevent arbitrary script execution when displaying email content?</strong><br/>
                <em>Answer:</em> All HTML email bodies are parsed through JSoup's safe DOM tree, stripping active script tags and event handlers. In reports and UI labels, all untrusted inputs are passed through <code>SecurityUtils.escapeHtml()</code>.</p>

                <p><strong>Q3: How does MailShield avoid scoring bias when an email has multiple similar urgency keywords?</strong><br/>
                <em>Answer:</em> The <code>DefaultRiskScoringEngine</code> imposes strict category ceiling caps (e.g. max 30 points for Social Engineering), ensuring multiple correlated indicators cannot independently inflate a benign email into a false positive.</p>
            </body>
            </html>
            """;

        editorPane.setText(html);
        editorPane.setCaretPosition(0);

        JScrollPane scrollPane = new JScrollPane(editorPane);
        scrollPane.setBorder(BorderFactory.createLineBorder(UiTheme.BORDER_COLOR, 1));
        card.add(scrollPane, BorderLayout.CENTER);

        add(card, BorderLayout.CENTER);
    }
}

