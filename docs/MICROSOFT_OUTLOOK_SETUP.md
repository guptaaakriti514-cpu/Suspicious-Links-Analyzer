# Microsoft Outlook / Office 365 Entra ID Integration Guide

This guide explains how to register MailShield in Microsoft Entra ID (formerly Azure Active Directory) to enable read-only mail synchronization via the official Microsoft Graph API.

> [!IMPORTANT]
> MailShield requests **delegated user permissions** with the minimum scope: `Mail.Read`. The application **never** collects, sees, or handles your Microsoft account password.

---

## Step 1: Open Microsoft Entra Admin Center
1. Sign in to the [Microsoft Entra admin center](https://entra.microsoft.com/) (or [Azure Portal](https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/RegisteredApps)).
2. In the left navigation pane, expand **Applications** &rarr; select **App registrations**.

---

## Step 2: Register a New Application
1. Click **+ New registration** at the top.
2. Enter the following details:
   - **Name:** `MailShield Forensic Platform`
   - **Supported account types:**
     - Select: *Accounts in any organizational directory (Any Microsoft Entra ID tenant - Multitenant) and personal Microsoft accounts (e.g. Skype, Xbox, Outlook.com)*
   - **Redirect URI (optional):**
     - Select Platform: **Public client/native (mobile & desktop)**
     - URI: `https://login.microsoftonline.com/common/oauth2/nativeclient`
3. Click **Register**.

---

## Step 3: Copy Application (Client) ID
1. On the app **Overview** page, note the following values:
   - **Application (client) ID:** (e.g., `8f8a1234-5678-abcd-ef01-234567890abc`)
   - **Directory (tenant) ID:** `common` (or your organizational Tenant ID if single-tenant)

---

## Step 4: Add Delegated Mail.Read Permission
1. In the left menu, select **API permissions**.
2. Click **+ Add a permission**.
3. Choose **Microsoft Graph** &rarr; select **Delegated permissions**.
4. In the search box, type `Mail.Read`.
5. Check the box next to `Mail.Read` (Read mail in all mailboxes).
6. Click **Add permissions**.

---

## Step 5: Configure MailShield
Add your Entra ID credentials to your `.env` file:
```env
MAILSHIELD_OUTLOOK_CLIENT_ID=your-microsoft-entra-client-id
MAILSHIELD_OUTLOOK_TENANT_ID=common
```
Or paste them into **Settings & Security** (Screen 9) inside the application.

---

## Step 6: Authenticate via Microsoft Device Code Flow
1. Open MailShield and navigate to **Connected Inboxes** (Screen 3).
2. Click **Connect Outlook**.
3. MailShield will output the official Microsoft Device Code instructions:
   ```
   To sign in, use a web browser to open the page https://microsoft.com/devicelogin
   and enter the code XXXXXXXX to authenticate.
   ```
4. Enter the code in your browser, sign in with your Outlook/365 account, and approve read access.
5. MailShield will automatically update:
   ```
   Status: Connected (Authorized via Microsoft Entra)
   Authorized Mailbox: analyst@outlook.com
   ```
6. Click **Sync (10 Msgs)** to ingest and analyze inbox messages with digital forensics integrity.

