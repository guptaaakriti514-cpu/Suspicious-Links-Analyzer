# MailShield Enterprise OAuth 2.0 & Cloud Provider Setup Guide

This document is for the **MailShield Platform Owner / Administrator**.

Normal users never need to configure client IDs, secrets, or technical parameters. Once the platform owner registers the MailShield application in Google Cloud and Microsoft Entra ID and populates `.env`, end-users simply click **"Connect Gmail"** or **"Connect Outlook"** for a seamless, 1-click SaaS authentication experience.

---

## 1. Architecture & Security Model

MailShield connects to cloud email providers strictly via **OAuth 2.0 Authorization Code Flow with PKCE**:
- **Least-Privilege Scopes:**
  - Google: `https://www.googleapis.com/auth/gmail.readonly`
  - Microsoft: `https://graph.microsoft.com/Mail.Read` + `User.Read`
- **Zero Password Handling:** MailShield redirects directly to official Google (`accounts.google.com`) and Microsoft (`login.microsoftonline.com`) consent portals in the system browser.
- **AES-256-GCM Vault:** Stored refresh tokens and session credentials are encrypted at rest with military-grade AES-256 authenticated encryption using random 96-bit IVs and 128-bit authentication tags to prevent tampering.
- **100% Local Digital Forensics:** All email parsing, forensic hashing (SHA-256), and multi-vector threat detection run locally on the analyst's workstation.

---

## 2. Google Cloud Console Setup (One-Time Setup)

### Step 1: Create or Select a Google Cloud Project
1. Navigate to the [Google Cloud Console](https://console.cloud.google.com/).
2. Click the project dropdown at the top and select **New Project**. Name it `MailShield Platform`.

### Step 2: Enable the Gmail API
1. In the navigation menu, go to **APIs & Services** &rarr; **Library**.
2. Search for `Gmail API` and click **Enable**.

### Step 3: Configure the OAuth Consent Screen
1. Go to **APIs & Services** &rarr; **OAuth consent screen**.
2. Select **External** (or **Internal** if within a Google Workspace organization) and click **Create**.
3. Fill in:
   - **App name:** `MailShield`
   - **User support email:** Your email address
   - **Developer contact information:** Your email address
4. Under **Scopes**, click **Add or Remove Scopes**:
   - Filter and select: `.../auth/gmail.readonly` (`Read, compose, send, and permanently delete all your email from Gmail` is NOT required — only select **View your email messages and settings**).
5. Under **Test Users** (crucial for Google apps in Testing status):
   - Add the Gmail email addresses you will use to sign in to MailShield.
6. Save and finish.

### Step 4: Create OAuth 2.0 Desktop Credentials
1. Go to **APIs & Services** &rarr; **Credentials**.
2. Click **Create Credentials** &rarr; **OAuth client ID**.
3. Under **Application type**, select **Desktop app**.
4. Set the name to `MailShield Desktop Client`.
5. Click **Create**.
6. Copy the generated **Client ID** and **Client Secret**.

### Step 5: Update `.env`
In your `Suspicious-Links-Analyzer/.env` file:
```env
MAILSHIELD_GMAIL_CLIENT_ID=your-google-client-id.apps.googleusercontent.com
MAILSHIELD_GMAIL_CLIENT_SECRET=GOCSPX-your-google-client-secret
MAILSHIELD_GMAIL_REDIRECT_PORT=8888
```

---

## 3. Microsoft Entra Admin Center Setup (One-Time Setup)

### Step 1: Register an Application in Microsoft Entra ID
1. Navigate to the [Microsoft Entra Admin Center](https://entra.microsoft.com/) (or [Azure Portal App Registrations](https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade)).
2. Click **New registration**.
3. Fill in the registration form:
   - **Name:** `MailShield Email Security`
   - **Supported account types:** Select **Accounts in any organizational directory (Any Microsoft Entra ID tenant - Multitenant) and personal Microsoft accounts (e.g. Skype, Xbox, Outlook.com)**.
   - **Redirect URI:**
     - Select platform: **Mobile and desktop applications** (or Public client/native).
     - Enter URI: `http://localhost:8889`
4. Click **Register**.

### Step 2: Configure API Permissions
1. In your application overview, go to **API permissions**.
2. Click **Add a permission** &rarr; **Microsoft Graph** &rarr; **Delegated permissions**.
3. Search and select:
   - `Mail.Read` (Read user mail)
   - `User.Read` (Sign in and read user profile)
4. Click **Add permissions**.

### Step 3: Enable Public Client Flow
1. In the left navigation, go to **Authentication**.
2. Under **Advanced settings** &rarr; **Allow public client flows**:
   - Toggle **Enable the following mobile and desktop flows** to **Yes**.
3. Save changes.

### Step 4: Update `.env`
In your `Suspicious-Links-Analyzer/.env` file:
```env
MAILSHIELD_OUTLOOK_CLIENT_ID=your-microsoft-entra-application-id
MAILSHIELD_OUTLOOK_TENANT_ID=common
```
*(Use `common` for multi-tenant and personal Outlook/Hotmail accounts, or your specific Tenant ID for single-tenant corporate environments).*

---

## 4. Master Key Encryption Configuration (Optional)

By default, MailShield automatically generates a cryptographically secure 256-bit AES master key at startup and stores it with restricted file permissions in:
`data/credentials/master.key`

To provide your own external master key via environment variable:
```env
# 32-byte Base64-encoded AES-256 key
MAILSHIELD_MASTER_KEY=U0FNUExFQUVTMjU2S0VZSEVSRTMyQllURVNMSU5FMTI=
```

---

## 5. End-User SaaS Experience

Once the administrator has configured the credentials above in `.env`:
1. The user opens MailShield.
2. The user sees the prominent **"Secure your inbox with MailShield"** onboarding banner.
3. The user clicks **Connect Gmail** or **Connect Outlook**.
4. The system browser opens automatically to the official Google or Microsoft authentication portal.
5. The user selects their account and approves read-only access.
6. The user is automatically redirected back to MailShield.
7. The mailbox immediately displays **● Connected & Active** with the user's email address.
8. MailShield immediately starts incremental background synchronization and multi-vector threat analysis!
