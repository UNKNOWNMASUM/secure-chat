# Secure Chat

A minimal encrypted messaging app: email + password sign in, JWT auth,
messages encrypted at rest with AES-256-GCM.

## How to run this on Replit

1. Create a new Replit project (Python template), or open your existing
   `secure-chat` Repl.
2. Upload/replace these files:
   - `main.py`
   - `requirements.txt`
   - `.replit`
   - `static/index.html`
3. In Replit's **Shell**, run:
   ```
   pip install -r requirements.txt
   ```
4. (Recommended) In Replit's **Secrets** tab (padlock icon), add:
   - `JWT_SECRET` — any long random string
   - `MESSAGE_ENC_KEY` — a base64-encoded 32-byte key. You can generate one
     by running this once in the Shell:
     ```
     python3 -c "import base64,os; print(base64.b64encode(os.urandom(32)).decode())"
     ```
     Copy the output into the `MESSAGE_ENC_KEY` secret.
     (If you skip this, the app still works, but stored messages become
     unreadable if the server restarts, since a new random key is generated
     each time.)
5. Click **Run**. Replit will start the server and open a webview.

## What was fixed vs. the previous version

- Sign-in now uses a real backend (FastAPI) with the standard OAuth2
  password flow, so the email field posts to `/api/login` correctly instead
  of failing silently.
- Passwords are hashed with bcrypt — never stored in plain text.
- Messages are encrypted with AES-256-GCM before being saved to the
  database, and decrypted only when shown to a logged-in participant.
- Fixed a JavaScript bug in the sign-in/sign-up toggle link that would
  have thrown an error in the browser console.
- Added clear on-screen error messages (wrong password, user not found,
  network errors) instead of the page doing nothing.

## Using the app

1. Open the site → you'll see a **Sign in** form.
2. Click **Sign up** to create an account with an email + password
   (min. 6 characters).
3. After signing up you're logged in automatically. To chat, type the
   email of another registered user in the "Chat with" field.
4. Type a message and press **Send** or hit Enter. Messages refresh
   automatically every 3 seconds.

## Project structure

```
secure-chat/
├── main.py            FastAPI backend (auth, encryption, API routes)
├── requirements.txt   Python dependencies
├── .replit            Replit run configuration
└── static/
    └── index.html     Frontend (sign in/up + chat UI)
```
