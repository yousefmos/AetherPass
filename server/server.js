/* ==========================================================================
   AetherPass Sync Server - Hybrid PostgreSQL & JSON File Database
   ========================================================================== */

const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
const os = require('os');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'aetherpass_super_secret_key_1337';
const DB_FILE = path.join(__dirname, 'database.json');

// Middleware
app.use(cors());
app.use(express.json());

// Serve static frontend assets from parent directory
app.use(express.static(path.join(__dirname, '..')));

// ==========================================================================
// Database Configuration & Abstraction
// ==========================================================================

let dbType = 'json';
let pool = null;

if (process.env.DATABASE_URL) {
    const { Pool } = require('pg');
    pool = new Pool({
        connectionString: process.env.DATABASE_URL,
        // Render/Supabase use self-signed certificates on their free tier databases,
        // requiring rejectUnauthorized to be disabled for Node.js connections.
        ssl: {
            rejectUnauthorized: false
        }
    });
    dbType = 'postgres';
    console.log("⚡ Database: PostgreSQL Mode Enabled");
} else {
    console.log("📂 Database: Local JSON File Mode Enabled");
}

/**
 * Initializes tables in PostgreSQL or checks database.json file locally
 */
async function initDB() {
    if (dbType === 'postgres') {
        try {
            // Create tables inside Transaction
            const client = await pool.connect();
            try {
                await client.query('BEGIN');
                await client.query(`
                    CREATE TABLE IF NOT EXISTS users (
                        id VARCHAR(50) PRIMARY KEY,
                        username VARCHAR(50) UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                `);
                await client.query(`
                    CREATE TABLE IF NOT EXISTS vaults (
                        user_id VARCHAR(50) PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
                        vault_data TEXT NOT NULL,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                `);
                await client.query('COMMIT');
                console.log("✅ Database: PostgreSQL Tables Ready");
            } catch (err) {
                await client.query('ROLLBACK');
                throw err;
            } finally {
                client.release();
            }
        } catch (err) {
            console.error("❌ Database: PostgreSQL initialization failed, falling back to local JSON:", err);
            dbType = 'json';
            initJSONDB();
        }
    } else {
        initJSONDB();
    }
}

function initJSONDB() {
    if (!fs.existsSync(DB_FILE)) {
        const initialData = {
            users: [],
            vaults: {}
        };
        fs.writeFileSync(DB_FILE, JSON.stringify(initialData, null, 2), 'utf8');
    }
    console.log("✅ Database: Local JSON Database Ready");
}

// JSON Database Helper Utilities
function readJSONDB() {
    try {
        const data = fs.readFileSync(DB_FILE, 'utf8');
        return JSON.parse(data);
    } catch (e) {
        console.error("Error reading JSON database:", e);
        return { users: [], vaults: {} };
    }
}

function writeJSONDB(data) {
    try {
        fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2), 'utf8');
        return true;
    } catch (e) {
        console.error("Error writing to JSON database:", e);
        return false;
    }
}

// Abstraction API
async function findUserByUsername(username) {
    const cleanUsername = username.trim().toLowerCase();
    if (dbType === 'postgres') {
        const res = await pool.query('SELECT * FROM users WHERE username = $1', [cleanUsername]);
        return res.rows[0] || null;
    } else {
        const db = readJSONDB();
        return db.users.find(u => u.username === cleanUsername) || null;
    }
}

async function createUser(id, username, passwordHash) {
    const cleanUsername = username.trim().toLowerCase();
    if (dbType === 'postgres') {
        const client = await pool.connect();
        try {
            await client.query('BEGIN');
            await client.query('INSERT INTO users (id, username, password_hash) VALUES ($1, $2, $3)', [id, cleanUsername, passwordHash]);
            await client.query('INSERT INTO vaults (user_id, vault_data) VALUES ($1, $2)', [id, JSON.stringify([])]);
            await client.query('COMMIT');
            return true;
        } catch (err) {
            await client.query('ROLLBACK');
            throw err;
        } finally {
            client.release();
        }
    } else {
        const db = readJSONDB();
        const newUser = {
            id,
            username: cleanUsername,
            passwordHash,
            createdAt: new Date().toISOString()
        };
        db.users.push(newUser);
        db.vaults[id] = [];
        return writeJSONDB(db);
    }
}

async function getVault(userId) {
    if (dbType === 'postgres') {
        const res = await pool.query('SELECT vault_data FROM vaults WHERE user_id = $1', [userId]);
        if (res.rows[0]) {
            return JSON.parse(res.rows[0].vault_data);
        }
        return [];
    } else {
        const db = readJSONDB();
        return db.vaults[userId] || [];
    }
}

async function saveVault(userId, vaultArray) {
    if (dbType === 'postgres') {
        await pool.query(
            `INSERT INTO vaults (user_id, vault_data) 
             VALUES ($1, $2) 
             ON CONFLICT (user_id) 
             DO UPDATE SET vault_data = $2, updated_at = CURRENT_TIMESTAMP`,
            [userId, JSON.stringify(vaultArray)]
        );
        return true;
    } else {
        const db = readJSONDB();
        db.vaults[userId] = vaultArray;
        return writeJSONDB(db);
    }
}

// ==========================================================================
// Authentication Middleware
// ==========================================================================

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN
    
    if (!token) {
        return res.status(401).json({ success: false, error: "Access denied. Session token missing." });
    }
    
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(403).json({ success: false, error: "Invalid or expired session token." });
        }
        req.userId = decoded.userId;
        req.username = decoded.username;
        next();
    });
}

// ==========================================================================
// API Endpoints
// ==========================================================================

// Register Account
app.post('/api/auth/register', async (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ success: false, error: "Username and password are required." });
    }
    
    const cleanUsername = username.trim().toLowerCase();
    if (cleanUsername.length < 3) {
        return res.status(400).json({ success: false, error: "Username must be at least 3 characters long." });
    }
    
    if (password.length < 6) {
        return res.status(400).json({ success: false, error: "Password must be at least 6 characters long." });
    }
    
    try {
        const userExists = await findUserByUsername(cleanUsername);
        if (userExists) {
            return res.status(400).json({ success: false, error: "Username is already registered." });
        }
        
        // Hash user password
        const passwordHash = bcrypt.hashSync(password, 10);
        const userId = Date.now().toString() + Math.random().toString().substr(2, 5);
        
        await createUser(userId, cleanUsername, passwordHash);
        
        const token = jwt.sign({ userId, username: cleanUsername }, JWT_SECRET, { expiresIn: '30d' });
        return res.status(201).json({ success: true, token, username: cleanUsername });
    } catch (err) {
        console.error("Registration error:", err);
        return res.status(500).json({ success: false, error: "Registration failed." });
    }
});

// Login Account
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ success: false, error: "Username and password are required." });
    }
    
    const cleanUsername = username.trim().toLowerCase();
    
    try {
        const user = await findUserByUsername(cleanUsername);
        if (!user) {
            return res.status(400).json({ success: false, error: "Invalid username or password." });
        }
        
        // Check password (supports password_hash from pg and passwordHash from JSON DB)
        const hash = user.password_hash || user.passwordHash;
        const isMatch = bcrypt.compareSync(password, hash);
        if (!isMatch) {
            return res.status(400).json({ success: false, error: "Invalid username or password." });
        }
        
        const token = jwt.sign({ userId: user.id || user.userId, username: cleanUsername }, JWT_SECRET, { expiresIn: '30d' });
        return res.json({ success: true, token, username: cleanUsername });
    } catch (err) {
        console.error("Login error:", err);
        return res.status(500).json({ success: false, error: "Login failed." });
    }
});

// Fetch User Vault Data
app.get('/api/vault', authenticateToken, async (req, res) => {
    try {
        const vault = await getVault(req.userId);
        return res.json({ success: true, vault });
    } catch (err) {
        console.error("Fetch vault error:", err);
        return res.status(500).json({ success: false, error: "Failed to load vault data." });
    }
});

// Sync/Update User Vault Data
app.post('/api/vault', authenticateToken, async (req, res) => {
    const { vault } = req.body;
    
    if (!Array.isArray(vault)) {
        return res.status(400).json({ success: false, error: "Vault data must be a JSON array." });
    }
    
    try {
        await saveVault(req.userId, vault);
        return res.json({ success: true });
    } catch (err) {
        console.error("Save vault error:", err);
        return res.status(500).json({ success: false, error: "Database failed to save synchronization changes." });
    }
});

// Redirect root to dashboard
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'index.html'));
});

// Start Server and log connection URLs
initDB().then(() => {
    app.listen(PORT, () => {
        console.log(`\n=========================================================`);
        console.log(`⚡ AetherPass Server is active and running!`);
        console.log(`👉 Access on this machine: http://localhost:${PORT}`);
        
        // Find local networks IPs to display to the user
        const networkInterfaces = os.networkInterfaces();
        const localIPs = [];
        
        for (const interfaceName in networkInterfaces) {
            for (const iface of networkInterfaces[interfaceName]) {
                if (iface.family === 'IPv4' && !iface.internal) {
                    localIPs.push(iface.address);
                }
            }
        }
        
        if (localIPs.length > 0) {
            console.log(`\n📲 Access from other devices in the same network:`);
            localIPs.forEach(ip => {
                console.log(`   --> http://${ip}:${PORT}`);
            });
        }
        console.log(`=========================================================\n`);
    });
});
