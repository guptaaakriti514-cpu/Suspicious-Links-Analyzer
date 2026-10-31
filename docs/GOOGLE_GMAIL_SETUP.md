# Google Gmail API OAuth 2.0 Desktop Integration Guide

This guide details the step-by-step procedure for authorizing **MailShield** to connect to an authorized personal or workspace Gmail account using official Google OAuth 2.0 PKCE desktop authentication.

> [!IMPORTANT]
> MailShield requests **strictly read-only** mailbox access (`https://www.googleapis.com/auth/gmail.readonly`). MailShield **never** asks for, collects, or handles your Google account password.

---

## Prerequisites
- A Google Account (personal `@gmail.com` or Google Workspace).
- Access to [Google Cloud Console](https://console.cloud.google.com/).

---

## Step 1: Create a Project in Google Cloud Console
1. Navigate to [Google Cloud Console](https://console.cloud.google.com/).
2. Click the project dropdown in the top bar and select **New Project**.
3. Enter Project Name: `MailShield-Cybersecurity-SOC`.
4. Click **Create** and ensure your new project is selected.

---

## Step 2: Enable the Gmail API
1. In the left navigation menu, go to **APIs & Services** &rarr; **Library**.
2. In the search box, type `Gmail API` and press Enter.
3. Select **Gmail API** from the results and click the blue **Enable** button.

---

## Step 3: Configure OAuth Consent Screen
1. Go to **APIs & Services** &rarr; **OAuth consent screen**.
2. Select **External** (or **Internal** if using Google Workspace within an organization) and click **Create**.
3. Fill in the required fields:
   - **App name:** `MailShield Forensic Platform`
   - **User support email:** Your email address
   - **Developer contact information:** Your email address
4. Click **Save and Continue**.
5. On the **Scopes** page, click **Add or Remove Scopes**:
   - Filter by `gmail.readonly` or select `.../auth/gmail.readonly` (Read, compose, send, and permanently delete all your email from Gmail &mdash; *only Read access is requested*).
   - Click **Update** and **Save and Continue**.
6. On the **Test users** page:
   - Click **+ Add Users** and enter your personal Google email address (the mailbox you will test with).
   - Click **Save and Continue**.

---

## Step 4: Create Desktop OAuth Client Credentials
1. Go to **APIs & Services** &rarr; **Credentials**.
2. Click **+ Create Credentials** at the top and select **OAuth client ID**.
3. Under **Application type**, select **Desktop app**.
4. **Name:** `MailShield Desktop Client`.
5. Click **Create**.
6. A dialog will pop up showing your **Client ID** (e.g. `123456789-abc.apps.googleusercontent.com`) and **Client Secret**.

---

## Step 5: Configure MailShield
You have two easy ways to supply credentials to MailShield:

### Option A: Via `.env` File (Recommended)
1. Copy `.env.example` to `.env` in the project root:
   ```env
   MAILSHIELD_GMAIL_CLIENT_ID=your-client-id.apps.googleusercontent.com
   MAILSHIELD_GMAIL_CLIENT_SECRET=your-client-secret
   MAILSHIELD_GMAIL_REDIRECT_PORT=8888
   ```

### Option B: Via Application UI
1. Launch MailShield.
2. Open **Settings & Security** (Screen 9).
3. Paste your **Client ID** and **Client Secret** into the respective fields.

---

## Step 6: Connect & Authorize
1. Navigate to **Connected Inboxes** (Screen 3) in MailShield.
2. Under the **Google Gmail API** card, click **Connect Gmail**.
3. Your default web browser will open Google's official authorization screen.
4. Sign in with the test user account registered in Step 3.
5. If Google displays an *"Unverified app"* warning (normal for in-development academic apps), click **Advanced** &rarr; **Go to MailShield Forensic Platform (unsafe)**.
6. Grant read-only access to your emails.
7. The browser will confirm authentication, and MailShield will transition to:
   ```
   Status: Connected (Authorized via Google OAuth2)
   Authorized Mailbox: your.email@gmail.com
   ```
8. Click **Sync (10 Msgs)** to ingest and analyze recent emails on demand!

