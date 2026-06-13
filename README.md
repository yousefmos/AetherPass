# AetherPass // Liquid Glass Password Manager

AetherPass is a local-first, highly secure credential vault featuring a premium monochromatic liquid glass aesthetic. It runs entirely inside your browser offline, generating Time-Based One-Time Passwords (TOTP) and securing your online presence without relying on external servers.

![Liquid Glass Interface Design](https://img.shields.io/badge/Aesthetic-Liquid%20Glass-black)
![License](https://img.shields.io/badge/License-MIT-white)
![Build](https://img.shields.io/badge/Platform-HTML5%20%2F%20JS-silver)

---

## ✨ Features

- **Monochromatic Liquid Glass Aesthetics**: A high-end obsidian layout with dynamically flowing organic blobs drifting in the background behind frosted glassmorphic cards.
- **Dynamic Brand Colors**: Monochromatic icons light up with subtle glowing brand colors (Google Blue, YouTube Red, Discord Indigo) when hovered.
- **Local-First Storage**: Credential data is stored securely and directly in your browser's local sandbox (`localStorage`).
- **Dynamic 2FA TOTP Generator**: Generates 2FA verification codes locally utilizing the browser's native **Web Crypto API (HMAC-SHA1)**. Displays a visual 30-second countdown progress ring.
- **One-Click Quick Actions**: Hover over cards to quickly copy emails or passwords to your clipboard with immediate success indicators.
- **Built-in Password Generator**: Quickly generate cryptographically secure passwords.
- **Export & Import Vaults**: Easily backup your encrypted vault to a local `.json` file and restore it on any machine.
- **Responsive Layout**: Seamlessly adapted for mobile devices, tablets, and full desktops.

---

## 🚀 Quick Start

To enable cloud synchronization across multiple devices, run the Express backend server:

### Step 1: Install Server Dependencies
Open a terminal in the project directory, navigate to the `server` folder, and install the required packages:
```bash
cd server
npm install
```

### Step 2: Start the Server
Start the unified Express application:
```bash
npm start
```
This serves the frontend dashboard at the same port as the authentication and sync API!

### Step 3: Access AetherPass
- **On your host machine (Mac)**: Navigate to `http://localhost:3000`.
- **On other devices (Phones, Tablets)**: Make sure the device is connected to the **same Wi-Fi network**. Open your browser and navigate to `http://<MAC-IP>:3000` (the server terminal prints your exact IP address automatically upon launch).

---

## 🔒 Security & Architecture

1. **Hybrid Database Layer**:
   - **Local File Mode (Default)**: Falls back to `server/database.json` for lightweight offline testing.
   - **PostgreSQL Mode**: Connects to any PostgreSQL database (like Supabase, Neon.tech) if the `DATABASE_URL` environment variable is defined.
2. **Local Hashing**: Passwords are securely hashed on the server using `bcryptjs` with standard salts. Session state is authenticated using JWT tokens stored inside the browser's sandbox.
3. **Vault Sync**: When logged in, your local credentials array is synchronized with the server. If you save credentials offline, they will automatically merge with your cloud vault the next time you log in.

---

## ☁️ Deploying to Render with Persistent Database

To deploy AetherPass on Render and connect it to a free, permanent PostgreSQL database:

### Step 1: Create a Free PostgreSQL Database
1. Sign up for a free account at **[Supabase](https://supabase.com)** or **[Neon.tech](https://neon.tech)**.
2. Create a new project/database.
3. Go to the database connection settings and copy the **URI Connection String**. It looks like:
   `postgres://username:password@hostname:5432/dbname`

### Step 2: Deploy on Render
1. Create a free account at **[Render](https://render.com)**.
2. Push your AetherPass project files to a **GitHub repository** (ensure `package.json` is at the root).
3. In Render dashboard, click **New +** and select **Web Service**.
4. Connect your GitHub repository.
5. In the settings, configure:
   - **Name**: `aetherpass`
   - **Runtime**: `Node`
   - **Build Command**: `npm install`
   - **Start Command**: `npm start`
6. Click **Advanced** and add the following Environment Variable:
   - **Key**: `DATABASE_URL`
   - **Value**: *(Paste your Supabase/Neon connection string here)*
7. Click **Create Web Service**.

Once deployed, Render will create the database tables automatically. Your credentials will now sync permanently and securely to the cloud!
