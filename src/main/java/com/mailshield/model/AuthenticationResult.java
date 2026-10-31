package com.mailshield.model;

import java.util.Objects;

/**
 * Parsed authentication verdict from Authentication-Results and Received-SPF headers.
 */
public final class AuthenticationResult {
    public enum AuthStatus {
        PASS("Pass", true),
        FAIL("Fail", false),
        SOFTFAIL("SoftFail", false),
        NEUTRAL("Neutral", false),
        NONE("None / Missing", false),
        PERM_ERROR("PermError", false),
        TEMP_ERROR("TempError", false),
        UNKNOWN("Unknown / Unparsed", false);

        private final String display;
        private final boolean positive;

        AuthStatus(String display, boolean positive) {
            this.display = display;
            this.positive = positive;
        }

        public String getDisplay() {
            return display;
        }

        public boolean isPositive() {
            return positive;
        }
    }

    private final AuthStatus spfStatus;
    private final String spfSender;
    private final AuthStatus dkimStatus;
    private final String dkimDomain;
    private final AuthStatus dmarcStatus;
    private final String dmarcPolicy;
    private final String rawHeader;
    private final boolean hasAuthenticationHeader;

    public AuthenticationResult(AuthStatus spfStatus, String spfSender, AuthStatus dkimStatus,
                                String dkimDomain, AuthStatus dmarcStatus, String dmarcPolicy,
                                String rawHeader, boolean hasAuthenticationHeader) {
        this.spfStatus = spfStatus != null ? spfStatus : AuthStatus.UNKNOWN;
        this.spfSender = spfSender != null ? spfSender : "";
        this.dkimStatus = dkimStatus != null ? dkimStatus : AuthStatus.UNKNOWN;
        this.dkimDomain = dkimDomain != null ? dkimDomain : "";
        this.dmarcStatus = dmarcStatus != null ? dmarcStatus : AuthStatus.UNKNOWN;
        this.dmarcPolicy = dmarcPolicy != null ? dmarcPolicy : "";
        this.rawHeader = rawHeader != null ? rawHeader : "";
        this.hasAuthenticationHeader = hasAuthenticationHeader;
    }

    public static AuthenticationResult missing() {
        return new AuthenticationResult(AuthStatus.NONE, "", AuthStatus.NONE, "", AuthStatus.NONE, "", "", false);
    }

    public AuthStatus getSpfStatus() {
        return spfStatus;
    }

    public String getSpfSender() {
        return spfSender;
    }

    public AuthStatus getDkimStatus() {
        return dkimStatus;
    }

    public String getDkimDomain() {
        return dkimDomain;
    }

    public AuthStatus getDmarcStatus() {
        return dmarcStatus;
    }

    public String getDmarcPolicy() {
        return dmarcPolicy;
    }

    public String getRawHeader() {
        return rawHeader;
    }

    public boolean isHasAuthenticationHeader() {
        return hasAuthenticationHeader;
    }

    public boolean hasAnyFailure() {
        return spfStatus == AuthStatus.FAIL || spfStatus == AuthStatus.SOFTFAIL ||
               dkimStatus == AuthStatus.FAIL || dmarcStatus == AuthStatus.FAIL;
    }

    @Override
    public String toString() {
        return String.format("SPF: %s | DKIM: %s | DMARC: %s",
                spfStatus.getDisplay(), dkimStatus.getDisplay(), dmarcStatus.getDisplay());
    }
}

