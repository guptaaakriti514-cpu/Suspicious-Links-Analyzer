package com.mailshield.ui;

import com.formdev.flatlaf.FlatDarkLaf;
import com.mailshield.model.RiskLevel;
import com.mailshield.model.Severity;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.EmptyBorder;
import java.awt.*;

/**
 * Visual styling constants and helper components for the Dark SOC Cyber Theme.
 */
public final class UiTheme {

    public static final Color BG_DARK = new Color(0x0F, 0x17, 0x2A);
    public static final Color CARD_BG = new Color(0x1E, 0x29, 0x3B);
    public static final Color SIDEBAR_BG = new Color(0x0B, 0x0F, 0x19);
    public static final Color BORDER_COLOR = new Color(0x33, 0x41, 0x55);
    public static final Color TEXT_PRIMARY = new Color(0xF8, 0xFA, 0xFC);
    public static final Color TEXT_MUTED = new Color(0x94, 0xA3, 0xB8);
    public static final Color ACCENT_CYAN = new Color(0x38, 0xBD, 0xF8);
    public static final Color ACCENT_BLUE = new Color(0x25, 0x63, 0xEB);

    public static final Color COLOR_CRITICAL = new Color(0xEF, 0x44, 0x44);
    public static final Color COLOR_HIGH = new Color(0xF9, 0x73, 0x16);
    public static final Color COLOR_MEDIUM = new Color(0xEA, 0xB3, 0x08);
    public static final Color COLOR_LOW = new Color(0x10, 0xB9, 0x81);
    public static final Color COLOR_INFO = new Color(0x64, 0x74, 0x8B);

    public static final Font FONT_TITLE = new Font("Segoe UI", Font.BOLD, 18);
    public static final Font FONT_HEADER = new Font("Segoe UI", Font.BOLD, 14);
    public static final Font FONT_REGULAR = new Font("Segoe UI", Font.PLAIN, 12);
    public static final Font FONT_BOLD = new Font("Segoe UI", Font.BOLD, 12);
    public static final Font FONT_SMALL = new Font("Segoe UI", Font.PLAIN, 11);
    public static final Font FONT_MONO = new Font("Consolas", Font.PLAIN, 12);

    private UiTheme() {}

    public static void setupFlatLaf() {
        try {
            FlatDarkLaf.setup();
            UIManager.put("Panel.background", BG_DARK);
            UIManager.put("Label.foreground", TEXT_PRIMARY);
            UIManager.put("TableHeader.background", CARD_BG);
            UIManager.put("TableHeader.foreground", TEXT_MUTED);
            UIManager.put("Table.background", BG_DARK);
            UIManager.put("Table.foreground", TEXT_PRIMARY);
            UIManager.put("Table.gridColor", BORDER_COLOR);
            UIManager.put("Table.selectionBackground", new Color(0x1E, 0x3A, 0x5F));
            UIManager.put("Table.selectionForeground", TEXT_PRIMARY);
            UIManager.put("TextArea.background", CARD_BG);
            UIManager.put("TextArea.foreground", TEXT_PRIMARY);
            UIManager.put("TextField.background", CARD_BG);
            UIManager.put("TextField.foreground", TEXT_PRIMARY);
            UIManager.put("ComboBox.background", CARD_BG);
            UIManager.put("ComboBox.foreground", TEXT_PRIMARY);
            UIManager.put("Button.arc", 6);
            UIManager.put("Component.arc", 6);
        } catch (Exception ignored) {}
    }

    public static JPanel createCardPanel() {
        JPanel panel = new JPanel();
        panel.setBackground(CARD_BG);
        panel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(BORDER_COLOR, 1),
                new EmptyBorder(12, 16, 12, 16)
        ));
        return panel;
    }

    public static JLabel createRiskBadge(RiskLevel level) {
        JLabel badge = new JLabel(" " + level.getLabel().toUpperCase() + " ");
        badge.setFont(new Font("Segoe UI", Font.BOLD, 11));
        badge.setOpaque(true);
        badge.setForeground(Color.WHITE);

        Color bg = switch (level) {
            case CRITICAL -> COLOR_CRITICAL;
            case HIGH -> COLOR_HIGH;
            case MEDIUM -> COLOR_MEDIUM;
            case LOW -> COLOR_LOW;
            case INSUFFICIENT_DATA -> COLOR_INFO;
        };
        badge.setBackground(bg);
        badge.setBorder(new EmptyBorder(2, 6, 2, 6));
        return badge;
    }

    public static JLabel createSeverityBadge(Severity severity) {
        JLabel badge = new JLabel(" " + severity.name() + " ");
        badge.setFont(new Font("Segoe UI", Font.BOLD, 10));
        badge.setOpaque(true);
        badge.setForeground(Color.WHITE);

        Color bg = switch (severity) {
            case CRITICAL -> COLOR_CRITICAL;
            case HIGH -> COLOR_HIGH;
            case MEDIUM -> COLOR_MEDIUM;
            case LOW -> COLOR_LOW;
            case INFO -> COLOR_INFO;
        };
        badge.setBackground(bg);
        badge.setBorder(new EmptyBorder(1, 4, 1, 4));
        return badge;
    }

    public static JButton createStyledButton(String text, Color accent) {
        JButton btn = new JButton(text);
        btn.setFont(FONT_BOLD);
        btn.setBackground(accent);
        btn.setForeground(Color.WHITE);
        btn.setFocusPainted(false);
        btn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        btn.setBorder(new EmptyBorder(6, 14, 6, 14));
        return btn;
    }
}

