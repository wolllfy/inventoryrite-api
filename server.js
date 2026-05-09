const express = require("express");
const cors = require("cors");
const axios = require("axios");
const crypto = require("crypto");
const path = require("path");
require("dotenv").config();

let Pool = null;
try {
    ({ Pool } = require("pg"));
} catch (error) {
    Pool = null;
}

const app = express();

app.use(cors());
app.use(express.json({
    verify: (req, res, buf) => {
        req.rawBody = buf ? buf.toString("utf8") : "";
    }
}));
app.use(express.urlencoded({ extended: true }));

const PORT = process.env.PORT || 3000;

const CLOVER_CLIENT_ID = process.env.CLOVER_CLIENT_ID?.trim();
const CLOVER_CLIENT_SECRET = process.env.CLOVER_CLIENT_SECRET?.trim();

const APP_BASE_URL = (process.env.APP_BASE_URL || "https://inventoryrite-api.onrender.com").replace(/\/$/, "");
const REDIRECT_URI = (process.env.REDIRECT_URI || `${APP_BASE_URL}/oauth-callback`).trim();

const CLOVER_ENV = (process.env.CLOVER_ENV || "sandbox").toLowerCase();
const IS_PRODUCTION_CLOVER = CLOVER_ENV === "production" || CLOVER_ENV === "prod" || CLOVER_ENV === "live";

const CLOVER_BASE_URL = IS_PRODUCTION_CLOVER
    ? "https://www.clover.com"
    : "https://sandbox.dev.clover.com";

const CLOVER_API_BASE_URL = IS_PRODUCTION_CLOVER
    ? "https://api.clover.com"
    : "https://apisandbox.dev.clover.com";

const CLOVER_ITEM_LIMIT = Number(process.env.CLOVER_ITEM_LIMIT || 100);
const REQUEST_TIMEOUT_MS = Number(process.env.REQUEST_TIMEOUT_MS || 20000);

const RATE_LIMIT_WINDOW_MS = Number(process.env.RATE_LIMIT_WINDOW_MS || 15 * 60 * 1000);
const RATE_LIMIT_MAX_REQUESTS = Number(process.env.RATE_LIMIT_MAX_REQUESTS || 300);
const CSRF_TOKEN_TTL_MS = Number(process.env.CSRF_TOKEN_TTL_MS || 2 * 60 * 60 * 1000);
const OAUTH_STATE_TTL_MS = Number(process.env.OAUTH_STATE_TTL_MS || 10 * 60 * 1000);
const SECURE_COOKIE_FLAG = APP_BASE_URL.startsWith("https://") ? "; Secure" : "";
const CLOVER_WEBHOOK_SECRET = process.env.CLOVER_WEBHOOK_SECRET?.trim() || "";
const CLOVER_APP_ID = process.env.CLOVER_APP_ID?.trim() || "";
const CLOVER_APP_NAME = process.env.CLOVER_APP_NAME?.trim() || "InventoryRite";
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY?.trim() || "";
const APP_VERSION = process.env.APP_VERSION || "1.0.0";

const REQUIRED_CLOVER_SCOPES = [
    "merchant_read",
    "item_read",
    "item_write",
    "employee_read",
    "inventory_read",
    "inventory_write"
];


const DATABASE_URL = process.env.DATABASE_URL?.trim() || "";
const USE_DATABASE = !!DATABASE_URL && !!Pool;

const dbPool = USE_DATABASE
    ? new Pool({
        connectionString: DATABASE_URL,
        ssl: process.env.PGSSLMODE === "disable" ? false : { rejectUnauthorized: false },
        max: Number(process.env.PG_POOL_MAX || 20),
        idleTimeoutMillis: Number(process.env.PG_IDLE_TIMEOUT_MS || 30000),
        connectionTimeoutMillis: Number(process.env.PG_CONNECTION_TIMEOUT_MS || 5000)
    })
    : null;

const cloverApi = axios.create({
    timeout: REQUEST_TIMEOUT_MS
});

/*
|--------------------------------------------------------------------------
| SECURITY MIDDLEWARE - RATE LIMIT, REQUEST IDS, CSRF, AND OAUTH STATE
|--------------------------------------------------------------------------
*/

const rateLimitStore = new Map();
const csrfTokens = new Map();
const oauthStates = new Map();

function createToken(bytes = 32) {
    return crypto.randomBytes(bytes).toString("hex");
}

function nowMs() {
    return Date.now();
}

function cleanupSecurityStores() {
    const now = nowMs();

    for (const [key, bucket] of rateLimitStore.entries()) {
        if (!bucket || bucket.resetAt <= now) rateLimitStore.delete(key);
    }

    for (const [token, expiresAt] of csrfTokens.entries()) {
        if (expiresAt <= now) csrfTokens.delete(token);
    }

    for (const [state, data] of oauthStates.entries()) {
        if (!data || data.expiresAt <= now) oauthStates.delete(state);
    }
}

function parseCookies(req) {
    const header = req.headers.cookie || "";
    return header.split(";").reduce((cookies, pair) => {
        const index = pair.indexOf("=");
        if (index > -1) {
            const key = pair.slice(0, index).trim();
            const value = pair.slice(index + 1).trim();
            if (key) cookies[key] = decodeURIComponent(value);
        }
        return cookies;
    }, {});
}

function issueCsrfToken() {
    cleanupSecurityStores();
    const token = createToken(24);
    csrfTokens.set(token, nowMs() + CSRF_TOKEN_TTL_MS);
    return token;
}

function verifyCsrfToken(req, res, next) {
    const csrfExemptPaths = new Set(["/clover-webhook", "/clover-uninstall", "/debug-test-clover-cost"]);

    if (csrfExemptPaths.has(req.path)) {
        return next();
    }

    if (!["POST", "PUT", "PATCH", "DELETE"].includes(req.method)) {
        return next();
    }

    const token = req.headers["x-csrf-token"] || req.body?.csrfToken || "";
    const expiresAt = csrfTokens.get(token);

    if (!token || !expiresAt || expiresAt <= nowMs()) {
        return res.status(403).json({
            success: false,
            message: "Security check failed. Please refresh the page and try again."
        });
    }

    csrfTokens.set(token, nowMs() + CSRF_TOKEN_TTL_MS);
    return next();
}

function rateLimit(req, res, next) {
    cleanupSecurityStores();

    const ip = req.headers["x-forwarded-for"]?.split(",")[0]?.trim() || req.socket.remoteAddress || "unknown";
    const key = `${ip}:${req.path}`;
    const now = nowMs();
    const existing = rateLimitStore.get(key);

    if (!existing || existing.resetAt <= now) {
        const resetAt = now + RATE_LIMIT_WINDOW_MS;
        rateLimitStore.set(key, { count: 1, resetAt });
        res.setHeader("X-RateLimit-Limit", String(RATE_LIMIT_MAX_REQUESTS));
        res.setHeader("X-RateLimit-Remaining", String(Math.max(0, RATE_LIMIT_MAX_REQUESTS - 1)));
        res.setHeader("X-RateLimit-Reset", String(Math.ceil(resetAt / 1000)));
        return next();
    }

    existing.count += 1;
    const remaining = Math.max(0, RATE_LIMIT_MAX_REQUESTS - existing.count);
    res.setHeader("X-RateLimit-Limit", String(RATE_LIMIT_MAX_REQUESTS));
    res.setHeader("X-RateLimit-Remaining", String(remaining));
    res.setHeader("X-RateLimit-Reset", String(Math.ceil(existing.resetAt / 1000)));

    if (existing.count > RATE_LIMIT_MAX_REQUESTS) {
        return res.status(429).json({
            success: false,
            message: "Too many requests. Please slow down and try again shortly."
        });
    }

    return next();
}

function cloverApiRateLimit(req, res, next) {
    cleanupSecurityStores();

    const ip = req.headers["x-forwarded-for"]?.split(",")[0]?.trim() || req.socket.remoteAddress || "unknown";
    const merchantKey = String(req.headers["x-merchant-id"] || req.body?.merchantId || req.query?.merchantId || ip).trim() || ip;
    const key = `clover-api:${merchantKey}`;
    const windowMs = 60 * 1000;
    const maxRequests = Number(process.env.CLOVER_API_RATE_LIMIT_MAX || 100);
    const now = nowMs();
    const existing = rateLimitStore.get(key);

    if (!existing || existing.resetAt <= now) {
        rateLimitStore.set(key, { count: 1, resetAt: now + windowMs });
        return next();
    }

    existing.count += 1;

    if (existing.count > maxRequests) {
        return res.status(429).json({
            success: false,
            message: "Clover API rate limit exceeded. Please wait a moment and try again."
        });
    }

    return next();
}

app.use((req, res, next) => {
    req.id = crypto.randomUUID ? crypto.randomUUID() : createToken(16);
    res.setHeader("X-Request-Id", req.id);
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-XSS-Protection", "1; mode=block");
    res.setHeader("X-Frame-Options", "SAMEORIGIN");
    res.setHeader("Referrer-Policy", "same-origin");
    res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
    res.setHeader(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self' https://api.clover.com https://apisandbox.dev.clover.com; frame-ancestors 'self' https://www.clover.com https://sandbox.dev.clover.com"
    );
    next();
});

app.use(rateLimit);
app.use(/^\/clover-(?!webhook|uninstall).*/, cloverApiRateLimit);
app.use("/item-costs", cloverApiRateLimit);
app.use("/item-cost", cloverApiRateLimit);
app.use(verifyCsrfToken);

/*
|--------------------------------------------------------------------------
| CONNECTION + COST STORAGE
|--------------------------------------------------------------------------
| Production path: PostgreSQL / Supabase / Render Postgres using DATABASE_URL.
| Demo fallback: in-memory storage so the app still runs before the DB is added.
|
| IMPORTANT: For real Clover App Market behavior, add pg to package.json and set
| DATABASE_URL in Render. Without DATABASE_URL, merchant cost data and tokens reset
| whenever Render restarts.
|--------------------------------------------------------------------------
*/

let latestCloverConnection = {
    connected: false,
    merchant_id: "",
    employee_id: "",
    access_token: "",
    refresh_token: "",
    token_expires_at: "",
    scopes: "",
    connected_at: ""
};

const fallbackItemCosts = {};


async function initDatabase() {
    if (!USE_DATABASE || !dbPool) {
        console.warn("DATABASE_URL/pg not available. Running in demo memory mode only.");
        return;
    }

    await dbPool.query(`
        CREATE TABLE IF NOT EXISTS merchant_connections (
            merchant_id TEXT PRIMARY KEY,
            employee_id TEXT,
            access_token TEXT NOT NULL,
            refresh_token TEXT,
            token_expires_at TIMESTAMPTZ,
            scopes TEXT,
            connected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
    `);



    await dbPool.query(`ALTER TABLE merchant_connections ADD COLUMN IF NOT EXISTS refresh_token TEXT;`);
    await dbPool.query(`ALTER TABLE merchant_connections ADD COLUMN IF NOT EXISTS token_expires_at TIMESTAMPTZ;`);
    await dbPool.query(`ALTER TABLE merchant_connections ADD COLUMN IF NOT EXISTS scopes TEXT;`);

    await dbPool.query(`
        CREATE TABLE IF NOT EXISTS item_costs (
            merchant_id TEXT NOT NULL,
            item_id TEXT NOT NULL,
            cost_cents INTEGER NOT NULL DEFAULT 0,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            PRIMARY KEY (merchant_id, item_id)
        );
    `);

    await dbPool.query(`CREATE INDEX IF NOT EXISTS idx_merchant_connections_updated_at ON merchant_connections(updated_at);`);
    await dbPool.query(`CREATE INDEX IF NOT EXISTS idx_item_costs_merchant_id ON item_costs(merchant_id);`);
    await dbPool.query(`CREATE INDEX IF NOT EXISTS idx_item_costs_updated_at ON item_costs(updated_at);`);

    const lastConnection = await dbPool.query(`
        SELECT merchant_id, employee_id, access_token, refresh_token, token_expires_at, scopes, connected_at
        FROM merchant_connections
        ORDER BY updated_at DESC
        LIMIT 1;
    `);

    if (lastConnection.rows.length > 0) {
        const row = lastConnection.rows[0];
        latestCloverConnection = {
            connected: true,
            merchant_id: row.merchant_id || "",
            employee_id: row.employee_id || "",
            access_token: decryptToken(row.access_token || ""),
            refresh_token: decryptToken(row.refresh_token || ""),
            token_expires_at: row.token_expires_at ? new Date(row.token_expires_at).toISOString() : "",
            scopes: row.scopes || "",
            connected_at: row.connected_at ? new Date(row.connected_at).toISOString() : ""
        };
    }

    console.log("Database ready: merchant_connections and item_costs tables verified.");
}

async function saveCloverConnection(connection) {
    latestCloverConnection = {
        connected: true,
        merchant_id: connection.merchant_id || "",
        employee_id: connection.employee_id || "",
        access_token: connection.access_token || "",
        refresh_token: connection.refresh_token || latestCloverConnection.refresh_token || "",
        token_expires_at: connection.token_expires_at || latestCloverConnection.token_expires_at || "",
        scopes: connection.scopes || latestCloverConnection.scopes || "",
        connected_at: connection.connected_at || new Date().toISOString()
    };

    if (!USE_DATABASE || !dbPool || !latestCloverConnection.merchant_id || !latestCloverConnection.access_token) {
        return latestCloverConnection;
    }

    await dbPool.query(
        `INSERT INTO merchant_connections (merchant_id, employee_id, access_token, refresh_token, token_expires_at, scopes, connected_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
         ON CONFLICT (merchant_id)
         DO UPDATE SET
            employee_id = EXCLUDED.employee_id,
            access_token = EXCLUDED.access_token,
            refresh_token = COALESCE(EXCLUDED.refresh_token, merchant_connections.refresh_token),
            token_expires_at = EXCLUDED.token_expires_at,
            scopes = EXCLUDED.scopes,
            connected_at = EXCLUDED.connected_at,
            updated_at = NOW();`,
        [
            latestCloverConnection.merchant_id,
            latestCloverConnection.employee_id,
            encryptToken(latestCloverConnection.access_token),
            latestCloverConnection.refresh_token ? encryptToken(latestCloverConnection.refresh_token) : null,
            latestCloverConnection.token_expires_at || null,
            latestCloverConnection.scopes || null,
            latestCloverConnection.connected_at
        ]
    );

    return latestCloverConnection;
}

async function getItemCostsForMerchant(merchantId) {
    if (!merchantId) return {};

    if (!USE_DATABASE || !dbPool) {
        return fallbackItemCosts[merchantId] || {};
    }

    const result = await dbPool.query(
        `SELECT item_id, cost_cents FROM item_costs WHERE merchant_id = $1;`,
        [merchantId]
    );

    const costs = {};
    result.rows.forEach((row) => {
        costs[row.item_id] = Number(row.cost_cents || 0);
    });

    return costs;
}

async function saveItemCostForMerchant(merchantId, itemId, costCents) {
    if (!merchantId || !itemId) {
        throw new Error("Missing merchantId or itemId.");
    }

    const normalizedCost = Math.max(0, Math.round(Number(costCents || 0)));

    if (!USE_DATABASE || !dbPool) {
        if (!fallbackItemCosts[merchantId]) fallbackItemCosts[merchantId] = {};
        fallbackItemCosts[merchantId][itemId] = normalizedCost;
        return normalizedCost;
    }

    await dbPool.query(
        `INSERT INTO item_costs (merchant_id, item_id, cost_cents, updated_at)
         VALUES ($1, $2, $3, NOW())
         ON CONFLICT (merchant_id, item_id)
         DO UPDATE SET cost_cents = EXCLUDED.cost_cents, updated_at = NOW();`,
        [merchantId, itemId, normalizedCost]
    );

    return normalizedCost;
}

/*
|--------------------------------------------------------------------------
| HELPERS
|--------------------------------------------------------------------------
*/

function safe(value) {
    return String(value || "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}

function formatTokenForDisplay(token) {
    if (!token) return "";
    if (token.length <= 10) return "Token saved";
    return token.substring(0, 6) + "..." + token.substring(token.length - 4);
}

function hasValidEncryptionKey() {
    return /^[a-f0-9]{64}$/i.test(ENCRYPTION_KEY);
}

function encryptToken(token) {
    if (!token) return "";
    if (!hasValidEncryptionKey()) return token;

    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", Buffer.from(ENCRYPTION_KEY, "hex"), iv);
    let encrypted = cipher.update(String(token), "utf8", "hex");
    encrypted += cipher.final("hex");
    const authTag = cipher.getAuthTag();
    return `enc:v1:${iv.toString("hex")}:${encrypted}:${authTag.toString("hex")}`;
}

function decryptToken(value) {
    if (!value) return "";
    const token = String(value);

    // Backward compatible: existing saved plaintext tokens still work.
    if (!token.startsWith("enc:v1:")) return token;

    if (!hasValidEncryptionKey()) {
        console.warn("Encrypted Clover token found, but ENCRYPTION_KEY is missing or invalid.");
        return "";
    }

    try {
        const parts = token.split(":");
        if (parts.length !== 5) {
            console.error("Invalid encrypted token format.");
            return "";
        }
        const [, , ivHex, encrypted, authTagHex] = parts;
        const decipher = crypto.createDecipheriv("aes-256-gcm", Buffer.from(ENCRYPTION_KEY, "hex"), Buffer.from(ivHex, "hex"));
        decipher.setAuthTag(Buffer.from(authTagHex, "hex"));
        let decrypted = decipher.update(encrypted, "hex", "utf8");
        decrypted += decipher.final("utf8");
        return decrypted;
    } catch (error) {
        console.error("Unable to decrypt Clover token:", error.message);
        return "";
    }
}

function logApiCall(endpoint, merchantId, method, status) {
    console.log(JSON.stringify({
        timestamp: new Date().toISOString(),
        endpoint,
        merchantId: merchantId || "",
        method,
        status,
        appVersion: APP_VERSION,
        cloverEnvironment: IS_PRODUCTION_CLOVER ? "production" : "sandbox"
    }));
}

async function refreshTokenIfNeeded(connection) {
    if (!connection || !connection.refresh_token || !connection.token_expires_at) {
        return connection;
    }

    const expiresAt = new Date(connection.token_expires_at).getTime();
    if (!Number.isFinite(expiresAt) || expiresAt - nowMs() > 5 * 60 * 1000) {
        return connection;
    }

    try {
        const tokenResponse = await cloverApi.post(
            `${CLOVER_API_BASE_URL}/oauth/token`,
            new URLSearchParams({
                client_id: CLOVER_CLIENT_ID,
                client_secret: CLOVER_CLIENT_SECRET,
                grant_type: "refresh_token",
                refresh_token: connection.refresh_token
            }).toString(),
            { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
        );

        const tokenData = tokenResponse.data || {};
        const expiresInSeconds = Number(tokenData.expires_in || tokenData.expiresIn || 0);

        return await saveCloverConnection({
            merchant_id: connection.merchant_id,
            employee_id: connection.employee_id,
            access_token: tokenData.access_token || connection.access_token,
            refresh_token: tokenData.refresh_token || connection.refresh_token,
            token_expires_at: expiresInSeconds ? new Date(nowMs() + expiresInSeconds * 1000).toISOString() : connection.token_expires_at,
            scopes: tokenData.scope || tokenData.scopes || connection.scopes || "",
            connected_at: connection.connected_at || new Date().toISOString()
        });
    } catch (error) {
        console.error("Clover token refresh failed:", error.response?.data || error.message);
        return connection;
    }
}

async function getConnectionFromRequest(req) {
    // Security note: tokens are intentionally not accepted from query strings.
    // The browser may send X-Merchant-Id, but bearer tokens stay server-side.
    let merchantFromRequest = req.headers["x-merchant-id"] || req.body?.merchantId || req.query.merchantId || "";
    merchantFromRequest = String(merchantFromRequest || "").trim();

    // Older frontend attempts used the word "server" as a placeholder. Do not
    // treat that as a real Clover merchant id.
    if (merchantFromRequest.toLowerCase() === "server") {
        merchantFromRequest = "";
    }

    let connection = latestCloverConnection;

    if (USE_DATABASE && dbPool) {
        let result;

        if (merchantFromRequest) {
            result = await dbPool.query(
                `SELECT merchant_id, employee_id, access_token, refresh_token, token_expires_at, scopes, connected_at
                 FROM merchant_connections
                 WHERE merchant_id = $1
                 LIMIT 1;`,
                [merchantFromRequest]
            );
        }

        // If the browser does not know the merchant id yet, fall back to the most
        // recently connected Clover merchant saved in the database. This keeps
        // inventory sync working after Render restarts/deploys.
        if (!result || result.rows.length === 0) {
            result = await dbPool.query(
                `SELECT merchant_id, employee_id, access_token, refresh_token, token_expires_at, scopes, connected_at
                 FROM merchant_connections
                 ORDER BY updated_at DESC
                 LIMIT 1;`
            );
        }

        if (result.rows.length > 0) {
            const row = result.rows[0];
            connection = {
                connected: true,
                merchant_id: row.merchant_id || "",
                employee_id: row.employee_id || "",

                // IMPORTANT FIX:
                // Tokens are stored encrypted in PostgreSQL by saveCloverConnection().
                // They must be decrypted before sending them to Clover.
                // Without this, Clover receives "enc:v1:..." instead of the real token
                // and returns 401 Unauthorized when loading inventory.
                access_token: decryptToken(row.access_token || ""),
                refresh_token: decryptToken(row.refresh_token || ""),

                token_expires_at: row.token_expires_at ? new Date(row.token_expires_at).toISOString() : "",
                scopes: row.scopes || "",
                connected_at: row.connected_at ? new Date(row.connected_at).toISOString() : ""
            };
        }
    }

    connection = await refreshTokenIfNeeded(connection);

    return {
        accessToken: connection.access_token || "",
        merchantId: connection.merchant_id || "",
        connection
    };
}

function cloverHeaders(accessToken) {
    return {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json",
        "User-Agent": `${CLOVER_APP_NAME || "InventoryRite"}/${APP_VERSION || "1.0.0"} (${APP_BASE_URL})`
    };
}

function getCloverError(error) {
    return {
        status: error.response?.status || 500,
        data: error.response?.data || error.message || "Unknown Clover error"
    };
}

function isValidMoneyCents(value) {
    const numberValue = Number(value);
    return !Number.isNaN(numberValue) && numberValue >= 0 && Number.isFinite(numberValue);
}



function getSuggestedPrice(costCents) {

    const targetMargin = 0.35;

    const rawPrice = costCents / (1 - targetMargin);

    const dollars = rawPrice / 100;

    return Math.max(0.99, Math.ceil(dollars) - 0.01);
}

function calculateMarginHealthScore(items) {

    let lowMarginCount = 0;
    let missingCostCount = 0;
    let duplicateCount = 0;

    const seenNames = new Set();

    items.forEach(item => {

        const cost = Number(item.cost || 0);
        const price = Number(item.price || 0);

        if (cost <= 0) {
            missingCostCount++;
        }

        if (price > 0 && cost > 0) {

            const margin = ((price - cost) / price) * 100;

            if (margin < 20) {
                lowMarginCount++;
            }
        }

        const normalizedName = String(item.name || "")
            .trim()
            .toLowerCase();

        if (normalizedName) {

            if (seenNames.has(normalizedName)) {
                duplicateCount++;
            }

            seenNames.add(normalizedName);
        }
    });

    const score =
        (lowMarginCount * 4) +
        (missingCostCount * 5) +
        (duplicateCount * 2);

    if (score <= 10) {
        return {
            label: "Excellent",
            className: "health-good"
        };
    }

    if (score <= 25) {
        return {
            label: "Good",
            className: "health-watch"
        };
    }

    if (score <= 45) {
        return {
            label: "Warning",
            className: "health-watch"
        };
    }

    return {
        label: "High Risk",
        className: "health-risk"
    };
}

/*
|--------------------------------------------------------------------------
| UI
|--------------------------------------------------------------------------
*/

function renderDashboard(options = {}) {
    const merchantId = options.merchant_id || latestCloverConnection.merchant_id || "";
    const employeeId = options.employee_id || latestCloverConnection.employee_id || "";
    const accessToken = options.access_token || latestCloverConnection.access_token || "";
    const csrfToken = issueCsrfToken();
    const connected = !!accessToken || latestCloverConnection.connected;
    const connectedAt = options.connected_at || latestCloverConnection.connected_at || "";

    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <meta name="clover-app-id" content="${safe(CLOVER_APP_ID)}" />
    <meta name="clover-app-name" content="${safe(CLOVER_APP_NAME)}" />
    <link rel="clover-webhook-config" href="/.well-known/clover.json" />
    <title>InventoryRite Profit Tools</title>
    <style>
        :root {
            --bg: #f5f7fb;
            --card: #ffffff;
            --text: #111827;
            --muted: #64748b;
            --line: #e5e7eb;
            --green: #15803d;
            --green-dark: #166534;
            --green-soft: #ecfdf5;
            --blue: #2563eb;
            --blue-soft: #eef2ff;
            --red: #b91c1c;
            --red-soft: #fee2e2;
            --amber: #b45309;
            --amber-soft: #fffbeb;
            --dark: #0f172a;
            --shadow: 0 16px 45px rgba(15, 23, 42, 0.08);
            --radius: 20px;
        }

        * { box-sizing: border-box; }

        html, body {
            width: 100%;
            max-width: 100%;
            overflow-x: hidden;
        }

        img, svg, table, input, button, select, textarea {
            max-width: 100%;
        }

        body {
            margin: 0;
            font-family: Arial, Helvetica, sans-serif;
            background:
                radial-gradient(circle at top left, rgba(22, 163, 74, 0.10), transparent 32%),
                linear-gradient(180deg, #f8fafc 0%, #eef2f7 100%);
            color: var(--text);
        }

        .topbar {
            background: rgba(255,255,255,0.94);
            border-bottom: 1px solid var(--line);
            padding: 16px 28px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            position: sticky;
            top: 0;
            z-index: 20;
            backdrop-filter: blur(12px);
        }

        .brand { display: flex; align-items: center; gap: 12px; }

        .logo {
            width: 44px;
            height: 44px;
            border-radius: 14px;
            background: linear-gradient(135deg, #16a34a, #14532d);
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: 900;
            letter-spacing: -1px;
            box-shadow: 0 10px 25px rgba(21, 128, 61, 0.25);
        }

        .brand h1 { margin: 0; font-size: 21px; line-height: 1.1; }
        .brand p { margin: 3px 0 0; color: var(--muted); font-size: 13px; }

        .badge {
            padding: 8px 12px;
            border-radius: 999px;
            font-size: 13px;
            font-weight: 800;
            border: 1px solid var(--line);
            background: #f9fafb;
        }

        .badge.connected { background: #ecfdf5; color: #166534; border-color: #bbf7d0; }
        .badge.disconnected { background: #fff7ed; color: #9a3412; border-color: #fed7aa; }

        .wrap { width: 100%; max-width: 1460px; margin: 18px auto; padding: 0 18px 42px; }

        .hero {
            background: rgba(255,255,255,0.96);
            border: 1px solid var(--line);
            border-radius: var(--radius);
            box-shadow: 0 12px 34px rgba(15, 23, 42, 0.065);
            padding: 18px 24px;
            margin-bottom: 18px;
            min-height: 118px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 18px;
            overflow: hidden;
            position: relative;
        }

        .hero:after {
            content: "";
            position: absolute;
            width: 190px;
            height: 190px;
            border-radius: 50%;
            right: -88px;
            top: -88px;
            background: rgba(34, 197, 94, 0.12);
            pointer-events: none;
        }

        .eyebrow {
            color: var(--green);
            font-weight: 900;
            letter-spacing: .08em;
            text-transform: uppercase;
            font-size: 11px;
            margin-bottom: 6px;
        }

        .hero h2 {
            margin: 0;
            font-size: 28px;
            line-height: 1.08;
            letter-spacing: -0.035em;
            max-width: 760px;
        }

        .hero p {
            margin: 8px 0 0;
            color: var(--muted);
            line-height: 1.45;
            max-width: 720px;
            font-size: 13px;
        }

        .hero-actions {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            position: relative;
            z-index: 2;
        }

        .card {
            background: rgba(255,255,255,0.96);
            border: 1px solid var(--line);
            border-radius: var(--radius);
            box-shadow: var(--shadow);
        }

        .btn {
            border: 0;
            border-radius: 13px;
            padding: 12px 16px;
            font-weight: 900;
            cursor: pointer;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            min-height: 42px;
            transition: transform .12s ease, opacity .12s ease;
            font-size: 13px;
            user-select: none;
        }

        .btn:hover { transform: translateY(-1px); }
        .btn:disabled { opacity: .58; cursor: not-allowed; transform: none; }

        .btn-primary { background: var(--green); color: white; box-shadow: 0 9px 20px rgba(21, 128, 61, 0.22); }
        .btn-primary:hover { background: var(--green-dark); }
        .btn-secondary { background: var(--blue-soft); color: #1d4ed8; }
        .btn-dark { background: #111827; color: white; }
        .btn-light { background: #f8fafc; color: #111827; border: 1px solid var(--line); }
        .btn-danger { background: var(--red-soft); color: var(--red); border: 1px solid #fecaca; }
        .btn-amber { background: var(--amber-soft); color: var(--amber); border: 1px solid #fde68a; }
        .btn-small { min-height: 34px; padding: 8px 11px; font-size: 12px; border-radius: 10px; }

        .inventory-card { padding: 24px; }

        .table-top {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            gap: 14px;
            margin-bottom: 16px;
        }

        .table-top h3 { margin: 0 0 6px; font-size: 23px; }
        .table-top p { margin: 0; color: var(--muted); font-size: 14px; line-height: 1.5; }

        .toolbar {
            display: flex;
            gap: 10px;
            align-items: center;
            flex-wrap: wrap;
            justify-content: flex-end;
        }

        .inventory-command-center {
            background: linear-gradient(135deg, #ffffff 0%, #f8fafc 100%);
            border: 1px solid #e2e8f0;
            border-radius: 18px;
            padding: 16px;
            margin: 0 0 16px;
            box-shadow: 0 8px 22px rgba(15, 23, 42, 0.045);
        }

        .command-center-top {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 16px;
            flex-wrap: wrap;
        }

        .command-copy {
            min-width: 230px;
        }

        .command-title {
            margin: 0;
            color: #0f172a;
            font-size: 14px;
            font-weight: 900;
            line-height: 1.15;
        }

        .command-subtitle {
            margin-top: 4px;
            color: #64748b;
            font-size: 12px;
            font-weight: 800;
            line-height: 1.35;
        }

        .command-search-actions {
            display: flex;
            align-items: center;
            justify-content: flex-end;
            gap: 10px;
            flex: 1;
            min-width: 360px;
            flex-wrap: wrap;
        }

        .command-search-actions .search-input {
            flex: 1 1 360px;
            min-width: 260px;
            max-width: none;
        }

        .command-search-actions .btn {
            min-width: 126px;
            white-space: nowrap;
        }

        .product-action-row {
            display: flex;
            justify-content: flex-end;
            align-items: center;
            gap: 10px;
            flex-wrap: wrap;
            margin: 0;
        }

        .product-action-row .btn {
            white-space: nowrap;
        }

        input {
            width: 100%;
            border: 1px solid #d1d5db;
            border-radius: 13px;
            padding: 12px 14px;
            font-size: 14px;
            outline: none;
            background: white;
        }

        input:focus {
            border-color: var(--green);
            box-shadow: 0 0 0 3px rgba(34, 197, 94, 0.15);
        }

        .search-input {
            min-width: 300px;
            max-width: 420px;
        }

        .add-panel {
            display: none;
            background: linear-gradient(135deg, #f8fafc 0%, #ffffff 100%);
            border: 1px solid #dbe4ee;
            border-radius: 18px;
            padding: 16px;
            margin: -4px 0 16px;
            box-shadow: 0 8px 22px rgba(15, 23, 42, 0.04);
        }

        .add-panel.show { display: block; }

        .add-panel-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            margin-bottom: 12px;
            flex-wrap: wrap;
        }

        .add-panel-title {
            margin: 0;
            font-size: 14px;
            font-weight: 900;
            color: #0f172a;
        }

        .add-panel-subtitle {
            margin-top: 3px;
            font-size: 12px;
            font-weight: 800;
            color: #64748b;
        }

        .add-grid {
            display: grid;
            grid-template-columns: minmax(260px, 1fr) 170px 140px;
            gap: 12px;
            align-items: end;
        }

        label {
            display: block;
            font-size: 13px;
            font-weight: 900;
            margin-bottom: 7px;
        }

        /* ----------------------------------------------------------------
        | BULK PRICE UPDATE PANEL
        ---------------------------------------------------------------- */

        .bulk-panel {
            display: none;
            background: linear-gradient(135deg, #fffbeb 0%, #fef3c7 100%);
            border: 1px solid #fde68a;
            border-radius: 16px;
            padding: 16px 18px;
            margin: 0 0 16px;
        }

        .bulk-panel.show { display: block; }

        .bulk-panel-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 14px;
            gap: 12px;
            flex-wrap: wrap;
        }

        .bulk-panel-title {
            font-size: 15px;
            font-weight: 900;
            color: #92400e;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .bulk-count-badge {
            background: #f59e0b;
            color: white;
            border-radius: 999px;
            padding: 3px 10px;
            font-size: 12px;
            font-weight: 900;
            min-width: 26px;
            text-align: center;
        }

        .bulk-controls {
            display: flex;
            gap: 10px;
            align-items: center;
            flex-wrap: wrap;
        }

        .bulk-pct-input {
            width: 90px;
            min-width: 90px;
            padding: 9px 10px;
            margin: 0;
            border-radius: 10px;
            border: 1px solid #fcd34d;
            background: white;
            font-weight: 900;
            font-size: 14px;
            text-align: center;
        }

        .bulk-pct-input:focus {
            border-color: #f59e0b;
            box-shadow: 0 0 0 3px rgba(245, 158, 11, 0.18);
        }

        .bulk-progress {
            display: none;
            margin-top: 12px;
            background: #fde68a;
            border-radius: 999px;
            height: 8px;
            overflow: hidden;
        }

        .bulk-progress.show { display: block; }

        .bulk-progress-bar {
            height: 100%;
            background: #f59e0b;
            border-radius: 999px;
            width: 0%;
            transition: width 0.3s ease;
        }

        .bulk-progress-label {
            font-size: 12px;
            color: #92400e;
            margin-top: 6px;
            font-weight: 800;
            display: none;
        }

        .bulk-progress-label.show { display: block; }

        .protected-pricing-note {
            margin-top: 12px;
            padding: 9px 11px;
            border-radius: 12px;
            background: #ffffff;
            border: 1px solid #fde68a;
            color: #92400e;
            font-size: 12px;
            font-weight: 900;
            line-height: 1.35;
        }

        /* ----------------------------------------------------------------
        | BULK TOOLBAR (floats above table when items are selected)
        ---------------------------------------------------------------- */

        .bulk-toolbar {
            display: none;
            background: #111827;
            color: white;
            border-radius: 14px;
            padding: 10px 14px;
            margin: 0 0 12px;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            flex-wrap: wrap;
        }

        .bulk-toolbar.show { display: flex; }

        .bulk-toolbar-left {
            font-size: 13px;
            font-weight: 800;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .bulk-toolbar-right {
            display: flex;
            gap: 8px;
            align-items: center;
            flex-wrap: wrap;
        }

        .btn-bulk-increase {
            background: #16a34a;
            color: white;
            border: 0;
        }

        .btn-bulk-increase:hover { background: #15803d; }

        .btn-bulk-decrease {
            background: #dc2626;
            color: white;
            border: 0;
        }

        .btn-bulk-decrease:hover { background: #b91c1c; }

        .btn-bulk-clear {
            background: rgba(255,255,255,0.12);
            color: white;
            border: 1px solid rgba(255,255,255,0.18);
        }

        /* ----------------------------------------------------------------
        | CHECKBOX COLUMN
        ---------------------------------------------------------------- */

        .col-check { width: 42px; text-align: center; }

        input[type="checkbox"] {
            width: 17px;
            height: 17px;
            min-width: 17px;
            border-radius: 5px;
            border: 2px solid #d1d5db;
            cursor: pointer;
            accent-color: #15803d;
            padding: 0;
            margin: 0;
        }

        tr.row-selected td { background: #f0fdf4 !important; }

        .stats-row {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 12px;
            margin: 14px 0 16px;
        }

        .stat-box {
            background: #f8fafc;
            border: 1px solid var(--line);
            border-radius: 14px;
            padding: 13px 14px;
        }

        .stat-label {
            color: var(--muted);
            font-size: 12px;
            font-weight: 800;
            margin-bottom: 5px;
        }

        .stat-value {
            font-size: 20px;
            font-weight: 900;
            color: var(--text);
        }

        .table-wrap {
            border: 1px solid var(--line);
            border-radius: 16px;
            overflow-x: hidden;
            overflow-y: visible;
            background: white;
            width: 100%;
            max-width: 100%;
        }

        table {
            width: 100%;
            max-width: 100%;
            border-collapse: collapse;
            table-layout: fixed;
        }

        th, td {
            padding: 12px 8px;
            border-bottom: 1px solid var(--line);
            text-align: left;
            font-size: 13px;
            vertical-align: middle;
            overflow-wrap: anywhere;
            word-break: break-word;
            min-width: 0;
        }

        th { background: #f8fafc; color: #334155; font-weight: 900; }
        tr:last-child td { border-bottom: 0; }
        td.muted { color: var(--muted); }

        /* Clean one-window table: these columns total 100%, so no horizontal page scroll. */
        .check-col { width: 4%; }
        .name-col { width: 38%; }
        .money-col { width: 13%; }
        .metric-col { width: 12%; }
        .actions-col { width: 20%; }
        .product-name-cell { min-width: 0; }
        .detail-grid {
            display: grid;
            grid-template-columns: 140px 1fr;
            gap: 10px 14px;
            margin-top: 16px;
            font-size: 14px;
        }
        .detail-label { color: var(--muted); font-weight: 900; }
        .detail-value { color: var(--text); font-weight: 700; word-break: break-word; }

        tr.row-updated { animation: rowFlash 1.4s ease; }

        @keyframes rowFlash {
            0% { background: #dcfce7; }
            100% { background: white; }
        }

        @keyframes rowBulkFlash {
            0% { background: #fef3c7; }
            100% { background: white; }
        }

        tr.row-bulk-updated { animation: rowBulkFlash 1.8s ease; }

        .pill {
            display: inline-flex;
            padding: 5px 9px;
            border-radius: 999px;
            font-size: 12px;
            font-weight: 900;
            border: 1px solid var(--line);
            background: #f8fafc;
        }

        .pill.good { color: #166534; background: #ecfdf5; border-color: #bbf7d0; }
        .pill.warn { color: #9a3412; background: #fff7ed; border-color: #fed7aa; }
        .pill.bad { color: #991b1b; background: #fee2e2; border-color: #fecaca; }
        .profit-positive { color: #166534; font-weight: 900; }
        .profit-negative { color: #991b1b; font-weight: 900; }
        tr.row-below-cost td { background: #fff1f2; }
        tr.row-below-cost.row-selected td { background: #fee2e2 !important; }

        .empty {
            padding: 28px;
            color: var(--muted);
            font-size: 14px;
            text-align: center;
            line-height: 1.6;
        }

        .empty strong {
            color: var(--text);
            display: block;
            margin-bottom: 5px;
            font-size: 15px;
        }

        .small-input {
            width: 100%;
            min-width: 0;
            max-width: 100%;
            padding: 9px 9px;
            margin: 0;
            border-radius: 10px;
        }

        .name-input {
            width: 100%;
            min-width: 0;
            max-width: 100%;
            padding: 9px 10px;
            margin: 0;
            border-radius: 10px;
        }

        .row-actions {
            display: flex;
            gap: 6px;
            flex-wrap: wrap;
            align-items: center;
        }

        .row-actions .btn-small {
            flex: 1 1 58px;
            min-width: 0;
            padding-left: 7px;
            padding-right: 7px;
            white-space: nowrap;
        }

        .setup-card {
            padding: 24px;
            text-align: center;
            max-width: 720px;
            margin: 40px auto;
        }

        .setup-card h2 {
            margin: 0 0 10px;
            font-size: 30px;
            letter-spacing: -0.03em;
        }

        .setup-card p {
            color: var(--muted);
            line-height: 1.6;
            margin: 0 0 18px;
        }

        .toast-wrap {
            position: fixed;
            right: 22px;
            bottom: 22px;
            display: grid;
            gap: 10px;
            z-index: 100;
        }

        .toast {
            background: #111827;
            color: white;
            border-radius: 14px;
            padding: 13px 15px;
            box-shadow: 0 14px 30px rgba(15, 23, 42, .22);
            max-width: 380px;
            font-size: 14px;
            line-height: 1.45;
        }

        .toast.success { background: #166534; }
        .toast.error { background: #991b1b; }
        .toast.info { background: #1e3a8a; }

        .modal-backdrop {
            display: none;
            position: fixed;
            inset: 0;
            background: rgba(15, 23, 42, 0.54);
            z-index: 200;
            align-items: center;
            justify-content: center;
            padding: 22px;
        }

        .modal-backdrop.show { display: flex; }

        .modal {
            width: 100%;
            max-width: 460px;
            background: white;
            border-radius: 20px;
            box-shadow: 0 24px 80px rgba(15, 23, 42, 0.28);
            border: 1px solid var(--line);
            padding: 24px;
        }

        .modal h3 { margin: 0 0 8px; font-size: 21px; }

        .modal p {
            margin: 0;
            color: var(--muted);
            line-height: 1.55;
            font-size: 14px;
        }

        .modal-actions {
            display: flex;
            justify-content: flex-end;
            gap: 10px;
            margin-top: 20px;
        }

        .footer { color: var(--muted); text-align: center; margin-top: 30px; font-size: 13px; }

        .dev-link {
            color: var(--muted);
            text-decoration: none;
            font-size: 12px;
        }



        /* ----------------------------------------------------------------
        | POLISHED MERCHANT TABLE UX
        ---------------------------------------------------------------- */

        .sync-note {
            margin-top: 8px;
            color: var(--muted);
            font-size: 12px;
            font-weight: 800;
        }

        .table-wrap {
            box-shadow: 0 10px 28px rgba(15, 23, 42, 0.04);
        }

        tbody tr {
            transition: background .15s ease, transform .12s ease;
        }

        tbody tr:hover td {
            background: #fafafa;
        }

        th {
            height: 46px;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: .035em;
        }

        td {
            height: 58px;
        }

        .name-input,
        .small-input {
            border-color: #e5e7eb;
            background: #ffffff;
            min-height: 38px;
            font-weight: 800;
        }

        .name-input {
            font-weight: 900;
        }

        .name-input:hover,
        .small-input:hover {
            border-color: #cbd5e1;
        }

        .row-actions {
            justify-content: flex-end;
        }

        .row-actions .btn-small {
            min-height: 36px;
            border-radius: 11px;
            font-weight: 900;
        }

        .icon-action {
            width: 38px;
            flex: 0 0 38px !important;
            padding-left: 0 !important;
            padding-right: 0 !important;
            font-size: 14px !important;
        }

        .merchant-hint {
            background: #f8fafc;
            border: 1px dashed #cbd5e1;
            color: #475569;
            border-radius: 14px;
            padding: 10px 12px;
            font-size: 13px;
            font-weight: 800;
            margin: 0 0 14px;
        }

        .loading-dot:after {
            content: "";
            animation: dots 1.2s steps(4, end) infinite;
        }

        @keyframes dots {
            0%, 20% { content: ""; }
            40% { content: "."; }
            60% { content: ".."; }
            80%, 100% { content: "..."; }
        }



        /* ----------------------------------------------------------------
        | MERCHANT CONTROL BAR - WORKING BUTTONS
        ---------------------------------------------------------------- */

        .merchant-control-bar {
            background: linear-gradient(135deg, #f8fafc 0%, #e2e8f0 100%);
            border: 1px solid #dbe4ee;
            border-radius: 18px;
            padding: 14px 16px;
            margin: 0 0 14px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            flex-wrap: wrap;
            box-shadow: 0 4px 12px rgba(15, 23, 42, 0.05);
        }

        .merchant-control-left {
            color: #1e293b;
            min-width: 220px;
        }

        .merchant-control-title {
            color: #1e293b;
            font-size: 14px;
            font-weight: 900;
            line-height: 1.1;
        }

        .merchant-control-subtitle {
            margin-top: 4px;
            color: #64748b;
            font-size: 11px;
            font-weight: 800;
            line-height: 1.3;
        }

        .merchant-control-actions {
            display: flex;
            align-items: center;
            justify-content: flex-end;
            gap: 8px;
            flex-wrap: wrap;
            flex: 1;
        }

        .control-btn {
            border: 0;
            border-radius: 11px;
            color: white;
            font-size: 12px;
            font-weight: 900;
            min-height: 34px;
            padding: 8px 12px;
            cursor: pointer;
            transition: transform .12s ease, opacity .12s ease, filter .12s ease;
        }

        .control-btn:hover { transform: translateY(-1px); filter: brightness(1.04); }
        .control-btn:disabled { opacity: .58; cursor: not-allowed; transform: none; }
        .control-neutral,
        .control-all,
        .control-low,
        .control-reorder,
        .control-export,
        .control-rules,
        .control-log {
            background: #f8fafc;
            color: #334155;
            border: 1px solid #cbd5e1;
        }
        .control-neutral:hover,
        .control-all:hover,
        .control-low:hover,
        .control-reorder:hover,
        .control-export:hover,
        .control-rules:hover,
        .control-log:hover {
            background: #eef2f7;
            border-color: #94a3b8;
        }
        .control-import { background:#16a34a; color: #ffffff; border: 1px solid #15803d; }
        .control-profit { background:#dc2626; color: #ffffff; border: 1px solid #b91c1c; }

        .view-filter-note {
            display:none;
            margin: 0 0 14px;
            padding: 10px 12px;
            border-radius: 13px;
            background: #eff6ff;
            border: 1px solid #bfdbfe;
            color: #1e3a8a;
            font-size: 13px;
            font-weight: 900;
        }

        .view-filter-note.show { display:block; }


        .last-action-strip {
            margin: 0 0 14px;
            padding: 10px 13px;
            border-radius: 14px;
            border: 1px solid #bbf7d0;
            background: linear-gradient(135deg, #f0fdf4 0%, #ecfeff 100%);
            color: #14532d;
            font-size: 13px;
            font-weight: 900;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 10px;
            flex-wrap: wrap;
        }

        .last-action-strip span {
            color: #475569;
            font-weight: 800;
        }

        .stat-value.stat-pop {
            animation: statPop .38s ease-out;
        }

        @keyframes statPop {
            0% { transform: scale(1); }
            45% { transform: scale(1.08); color: #15803d; }
            100% { transform: scale(1); }
        }

        .save-state {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            min-width: 70px;
            font-size: 11px;
            font-weight: 900;
            border-radius: 999px;
            padding: 5px 8px;
            background: #f8fafc;
            border: 1px solid #e5e7eb;
            color: #64748b;
            margin-left: 4px;
        }

        .save-state.saved {
            background: #ecfdf5;
            border-color: #bbf7d0;
            color: #166534;
        }

        .save-state.saving {
            background: #eff6ff;
            border-color: #bfdbfe;
            color: #1d4ed8;
        }

        .save-state.unsaved {
            background: #fffbeb;
            border-color: #fde68a;
            color: #92400e;
        }

        .modal-wide { max-width: 680px; }

        .insight-list {
            margin-top: 14px;
            display: grid;
            gap: 9px;
            max-height: 360px;
            overflow-y: auto;
        }

        .insight-row {
            border: 1px solid #e5e7eb;
            background: #f8fafc;
            border-radius: 13px;
            padding: 10px 12px;
            display: flex;
            justify-content: space-between;
            gap: 12px;
            font-size: 13px;
        }

        .insight-row strong { display:block; color:#111827; margin-bottom:3px; }
        .insight-row span { color:#64748b; font-weight:800; }



        .modal { animation: modalPop .16s ease-out; }
        @keyframes modalPop {
            from { opacity: 0; transform: translateY(8px) scale(.98); }
            to { opacity: 1; transform: translateY(0) scale(1); }
        }

        .insight-row {
            align-items: center;
        }

        .insight-row div:last-child span {
            display: inline-flex;
            border-radius: 999px;
            padding: 5px 9px;
            background: #eef2ff;
            color: #1d4ed8;
            font-size: 11px;
            font-weight: 900;
            white-space: nowrap;
        }



        /* ----------------------------------------------------------------
        | PRODUCTIVITY INTELLIGENCE HUB
        ---------------------------------------------------------------- */

        .productivity-hub {
            display: grid;
            grid-template-columns: repeat(5, minmax(150px, 1fr));
            gap: 10px;
            margin: 0 0 14px;
        }

        .productivity-card {
            border: 1px solid #e2e8f0;
            background: linear-gradient(135deg, #ffffff 0%, #f8fafc 100%);
            border-radius: 16px;
            padding: 12px;
            cursor: pointer;
            text-align: left;
            box-shadow: 0 7px 18px rgba(15, 23, 42, 0.045);
            transition: transform .12s ease, border-color .12s ease, box-shadow .12s ease;
        }

        .productivity-card:hover {
            transform: translateY(-1px);
            border-color: #bbf7d0;
            box-shadow: 0 10px 24px rgba(15, 23, 42, 0.07);
        }

        .productivity-kicker {
            color: #15803d;
            font-size: 10px;
            font-weight: 900;
            letter-spacing: .06em;
            text-transform: uppercase;
            margin-bottom: 5px;
        }

        .productivity-title {
            color: #0f172a;
            font-size: 13px;
            font-weight: 900;
            line-height: 1.2;
            margin-bottom: 4px;
        }

        .productivity-copy {
            color: #64748b;
            font-size: 11px;
            font-weight: 800;
            line-height: 1.35;
        }

        .risk-score-row {
            display: grid;
            grid-template-columns: 1fr 1fr 1fr;
            gap: 10px;
            margin: 0 0 14px;
        }

        .risk-score-box {
            border: 1px solid #e5e7eb;
            border-radius: 15px;
            background: #ffffff;
            padding: 12px 13px;
        }

        .risk-score-label {
            color: #64748b;
            font-size: 11px;
            font-weight: 900;
            text-transform: uppercase;
            letter-spacing: .035em;
            margin-bottom: 5px;
        }

        .risk-score-value {
            color: #111827;
            font-size: 19px;
            font-weight: 900;
        }

        .risk-score-help {
            color: #64748b;
            font-size: 11px;
            font-weight: 800;
            margin-top: 4px;
            line-height: 1.35;
        }

        .cleanup-tag {
            display: inline-flex;
            border-radius: 999px;
            padding: 4px 8px;
            font-size: 11px;
            font-weight: 900;
            background: #fff7ed;
            border: 1px solid #fed7aa;
            color: #9a3412;
            margin-left: 6px;
        }



        .intelligence-strip {
            display: grid;
            grid-template-columns: 1.1fr 1fr 1fr 1.2fr;
            gap: 10px;
            margin: 0 0 14px;
        }

        .intelligence-box {
            border: 1px solid #e2e8f0;
            background: linear-gradient(135deg, #ffffff 0%, #f8fafc 100%);
            border-radius: 16px;
            padding: 13px 14px;
            box-shadow: 0 7px 18px rgba(15, 23, 42, 0.04);
        }

        .intelligence-label { color: #64748b; font-size: 11px; font-weight: 900; text-transform: uppercase; letter-spacing: .04em; margin-bottom: 5px; }
        .intelligence-value { color: #0f172a; font-size: 21px; font-weight: 900; line-height: 1.1; }
        .intelligence-help { color: #64748b; font-size: 11px; font-weight: 800; margin-top: 5px; line-height: 1.35; }
        .health-good { color: #166534; }
        .health-watch { color: #b45309; }
        .health-risk { color: #b91c1c; }
        .severity-pill { display: inline-flex; border-radius: 999px; padding: 4px 8px; font-size: 10px; font-weight: 900; text-transform: uppercase; letter-spacing: .035em; margin-right: 6px; }
        .severity-critical { background: #fee2e2; color: #991b1b; border: 1px solid #fecaca; }
        .severity-warning { background: #fffbeb; color: #92400e; border: 1px solid #fde68a; }
        .severity-opportunity { background: #eff6ff; color: #1d4ed8; border: 1px solid #bfdbfe; }
        .severity-suggestion { background: #ecfdf5; color: #166534; border: 1px solid #bbf7d0; }
        .insight-fix-btn { border: 0; border-radius: 999px; background: #111827; color: white; font-size: 11px; font-weight: 900; padding: 7px 10px; cursor: pointer; white-space: nowrap; }
        .insight-fix-btn:hover { filter: brightness(1.08); }



        /* ----------------------------------------------------------------
        | FINAL POLISH - CLEAN MERCHANT LAUNCH UI
        ---------------------------------------------------------------- */

        .topbar {
            padding-top: 11px;
            padding-bottom: 11px;
        }

        .logo {
            width: 38px;
            height: 38px;
            border-radius: 12px;
            font-size: 14px;
        }

        .brand h1 { font-size: 19px; }
        .brand p { font-size: 12px; }

        .hero {
            min-height: 96px;
            padding-top: 16px;
            padding-bottom: 16px;
        }

        .hero h2 { font-size: 25px; }

        .merchant-control-actions {
            display: grid;
            grid-template-columns: repeat(5, minmax(116px, 1fr));
            width: 100%;
        }

        .merchant-control-actions .control-btn {
            width: 100%;
        }

        .merchant-control-left {
            flex: 0 0 250px;
        }

        .productivity-card {
            min-height: 104px;
        }

        .productivity-kicker {
            color: #475569;
        }





        /* ----------------------------------------------------------------
        | FINAL MARKETPLACE POLISH - ICONS, SPACING, TRUST STATUS
        ---------------------------------------------------------------- */

        .productivity-card {
            position: relative;
            padding-left: 48px;
        }

        .productivity-card::before {
            content: attr(data-icon);
            position: absolute;
            left: 13px;
            top: 14px;
            width: 24px;
            height: 24px;
            border-radius: 10px;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            background: #ecfdf5;
            border: 1px solid #bbf7d0;
            color: #166534;
            font-size: 13px;
            font-weight: 900;
            box-shadow: 0 5px 12px rgba(21, 128, 61, 0.10);
        }

        .productivity-card:hover {
            transform: translateY(-2px);
            border-color: #86efac;
            box-shadow: 0 14px 30px rgba(21, 128, 61, 0.12);
        }

        .last-saved-status {
            color: #166534 !important;
            font-weight: 900 !important;
            background: #ecfdf5;
            border: 1px solid #bbf7d0;
            border-radius: 999px;
            padding: 4px 9px;
            font-size: 12px;
        }

        .last-saved-status.synced {
            animation: savedPulse 1.4s ease-out;
        }

        @keyframes savedPulse {
            0% { box-shadow: 0 0 0 0 rgba(22, 101, 52, 0.28); }
            100% { box-shadow: 0 0 0 10px rgba(22, 101, 52, 0); }
        }

        tbody td {
            height: 66px;
            padding-top: 14px;
            padding-bottom: 14px;
        }

        .name-input,
        .small-input {
            min-height: 41px;
        }



        /* ----------------------------------------------------------------
        | CLEAN OPERATIONS SUMMARY - REPLACES CLUTTER DASHBOARD BOXES
        ---------------------------------------------------------------- */

        .operations-summary-strip {
            margin: 0 0 12px;
            border: 1px solid #bbf7d0;
            background: linear-gradient(135deg, #f0fdf4 0%, #ffffff 100%);
            border-radius: 14px;
            padding: 10px 12px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            flex-wrap: wrap;
            box-shadow: 0 6px 16px rgba(15, 23, 42, 0.035);
        }

        .operations-summary-main {
            display: flex;
            align-items: center;
            gap: 8px;
            min-width: 260px;
            flex: 1;
            color: #14532d;
            font-size: 12px;
            line-height: 1.35;
        }

        .operations-summary-main strong {
            color: #14532d;
            font-size: 12px;
            font-weight: 900;
            white-space: nowrap;
        }

        .operations-summary-main span {
            color: #475569;
            font-weight: 800;
        }

        .operations-summary-pills {
            display: flex;
            align-items: center;
            justify-content: flex-end;
            gap: 7px;
            flex-wrap: wrap;
        }

        .summary-pill {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            border-radius: 999px;
            padding: 5px 9px;
            background: #ffffff;
            border: 1px solid #dbeafe;
            color: #1e293b;
            font-size: 11px;
            font-weight: 900;
            white-space: nowrap;
        }

        .stats-row {
            margin-top: 12px;
            margin-bottom: 12px;
        }

        .merchant-control-bar {
            background: linear-gradient(135deg, #ffffff 0%, #f8fafc 100%);
        }

        @media (max-width: 760px) {
            .operations-summary-main { align-items: flex-start; flex-direction: column; gap: 3px; }
            .operations-summary-pills { justify-content: flex-start; }
        }

                /* ----------------------------------------------------------------
        | FINAL VALUE FEATURES - HISTORY, UNDO, DUPLICATES, COST LOCK, PRESETS
        ---------------------------------------------------------------- */

        .value-tools-row {
            display: grid;
            grid-template-columns: repeat(4, minmax(132px, 1fr));
            gap: 8px;
            width: 100%;
            margin-top: 8px;
        }

        .margin-preset-row {
            margin-top: 14px;
            padding-top: 12px;
            border-top: 1px dashed #f59e0b;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 10px;
            flex-wrap: wrap;
        }

        .margin-preset-copy {
            color: #92400e;
            font-size: 12px;
            font-weight: 900;
            line-height: 1.35;
        }

        .margin-preset-actions {
            display: flex;
            gap: 7px;
            flex-wrap: wrap;
        }

        .preset-btn {
            border: 1px solid #fcd34d;
            background: #ffffff;
            color: #92400e;
            border-radius: 999px;
            padding: 8px 11px;
            font-size: 12px;
            font-weight: 900;
            cursor: pointer;
        }

        .preset-btn:hover { background: #fffbeb; }

        .recent-sidebar {
            margin: 0 0 14px;
            border: 1px solid #dbeafe;
            background: linear-gradient(135deg, #ffffff 0%, #eff6ff 100%);
            border-radius: 16px;
            padding: 13px 14px;
            box-shadow: 0 7px 18px rgba(15, 23, 42, 0.045);
        }

        .recent-sidebar-top {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 10px;
            margin-bottom: 8px;
        }

        .recent-sidebar-title {
            color: #0f172a;
            font-size: 13px;
            font-weight: 900;
        }

        .recent-sidebar-subtitle {
            color: #64748b;
            font-size: 11px;
            font-weight: 800;
            margin-top: 2px;
        }

        .recent-list {
            display: grid;
            grid-template-columns: repeat(3, minmax(0, 1fr));
            gap: 8px;
        }

        .recent-item {
            border: 1px solid #e2e8f0;
            background: #ffffff;
            border-radius: 12px;
            padding: 9px 10px;
            min-height: 70px;
        }

        .recent-item strong {
            display: block;
            color: #111827;
            font-size: 12px;
            line-height: 1.25;
            margin-bottom: 3px;
        }

        .recent-item span {
            display: block;
            color: #64748b;
            font-size: 11px;
            font-weight: 800;
            line-height: 1.3;
        }

        .recent-empty {
            color: #64748b;
            font-size: 12px;
            font-weight: 800;
            padding: 8px 0 2px;
        }

        .row-missing-cost td { background: #fffbeb; }
        .row-missing-cost.row-selected td { background: #fef3c7 !important; }

        .cost-warning-chip {
            display: inline-flex;
            margin-top: 5px;
            border-radius: 999px;
            padding: 3px 7px;
            font-size: 10px;
            font-weight: 900;
            background: #fffbeb;
            border: 1px solid #fde68a;
            color: #92400e;
        }

        @media (max-width: 980px) {
            .value-tools-row { grid-template-columns: repeat(2, minmax(130px, 1fr)); }
            .recent-list { grid-template-columns: 1fr; }
        }

        @media (max-width: 620px) {
            .value-tools-row { grid-template-columns: 1fr; }
            .margin-preset-actions .preset-btn { flex: 1 1 70px; }
        }

        @media (max-width: 1100px) {
            .merchant-control-actions { grid-template-columns: repeat(3, minmax(112px, 1fr)); }
        }

        @media (max-width: 700px) {
            .merchant-control-actions { grid-template-columns: 1fr 1fr; }
            .hero h2 { font-size: 21px; }
        }

        @media (max-width: 980px) {
            .merchant-control-bar { align-items: flex-start; }
            .merchant-control-actions { justify-content: flex-start; }
        }

        @media (max-width: 980px) {
            .productivity-hub { grid-template-columns: 1fr 1fr; }
            .intelligence-strip { grid-template-columns: 1fr 1fr; }
            .risk-score-row { grid-template-columns: 1fr; }
            .hero, .stats-row, .add-grid { grid-template-columns: 1fr; }
            .hero { flex-direction: column; }
            .hero h2 { font-size: 22px; }
            .topbar { align-items: flex-start; gap: 14px; flex-direction: column; }
            .table-top { flex-direction: column; }
            .toolbar { width: 100%; justify-content: flex-start; }
            .command-center-top { align-items: flex-start; }
            .command-search-actions { width: 100%; min-width: 100%; justify-content: flex-start; }
            .command-search-actions .search-input { width: 100%; min-width: 100%; max-width: 100%; flex-basis: 100%; }
            .command-search-actions .btn { flex: 1 1 130px; }
            .product-action-row { justify-content: flex-start; margin-top: 0; }
            .search-input { width: 100%; min-width: 100%; max-width: 100%; }
            .bulk-controls { flex-direction: column; align-items: flex-start; }
            .stats-row { grid-template-columns: 1fr 1fr; }
            th, td { padding: 10px 6px; font-size: 12px; }
            .btn-small { padding: 7px 7px; font-size: 11px; }
            .row-actions { gap: 5px; }
        }

        @media (max-width: 700px) {
            .productivity-hub { grid-template-columns: 1fr; }
            .intelligence-strip { grid-template-columns: 1fr; }
            .stats-row { grid-template-columns: 1fr; }
            .wrap { padding: 0 10px 40px; }
            .inventory-card { padding: 14px; }
            .hero { padding: 16px; min-height: auto; }
            .hero h2 { font-size: 22px; }
            .table-wrap { border-radius: 12px; }
            th, td { padding: 9px 5px; font-size: 11px; }
            .check-col { width: 6%; }
            .name-col { width: 40%; }
            .money-col { width: 14%; }
            .metric-col { width: 10%; }
            .actions-col { width: 16%; }
            .add-grid { grid-template-columns: 1fr; }
            .command-search-actions .btn { flex-basis: 100%; }
            .row-actions .btn-small { flex-basis: 100%; }
        }


        /* ----------------------------------------------------------------
        | SIMPLIFIED MERCHANT UI - SIMPLE BY DEFAULT, ADVANCED ON DEMAND
        | Keeps all functionality but hides noisy panels until requested.
        ---------------------------------------------------------------- */

        .simple-hero {
            min-height: auto !important;
            padding: 24px 26px !important;
            align-items: center;
        }

        .simple-hero:after { display: none; }

        .simple-hero-copy { max-width: 720px; }

        .simple-hero h2 {
            font-size: 31px !important;
            line-height: 1.08;
            margin: 0;
        }

        .simple-hero p {
            font-size: 14px !important;
            max-width: 680px;
            margin-top: 9px;
        }

        .simple-hero-actions {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            justify-content: flex-end;
            position: relative;
            z-index: 2;
        }

        .simple-status-strip {
            border-color: #e5e7eb !important;
            background: #ffffff !important;
        }

        .inventory-command-center {
            box-shadow: none !important;
            border-color: #e5e7eb !important;
            background: #ffffff !important;
        }

        .command-search-actions .btn { min-width: 112px; }

        #merchantControlBar,
        #productivityHub,
        #operationsSummaryStrip,
        #lastActionStrip,
        #recentChangesPanel,
        #marginStatsRow,
        .merchant-hint {
            display: none !important;
        }

        body.show-advanced #merchantControlBar { display: flex !important; }
        body.show-advanced #productivityHub { display: grid !important; }
        body.show-advanced #operationsSummaryStrip { display: flex !important; }
        body.show-advanced #lastActionStrip { display: flex !important; }
        body.show-advanced #recentChangesPanel { display: block !important; }
        body.show-advanced #marginStatsRow { display: grid !important; }
        body.show-advanced .merchant-hint { display: block !important; }

        body.show-advanced #btnToggleAdvancedTop,
        body.show-advanced #btnHeroAdvanced {
            background: #111827;
            color: #ffffff;
            border-color: #111827;
        }

        .stats-row:first-of-type {
            margin-top: 4px;
        }

        .stat-box {
            box-shadow: none !important;
        }

        @media (max-width: 760px) {
            .simple-hero {
                flex-direction: column;
                align-items: flex-start;
            }

            .simple-hero-actions {
                width: 100%;
                justify-content: flex-start;
            }

            .simple-hero-actions .btn {
                flex: 1 1 140px;
            }
        }

    </style>
</head>
<body>

    <div class="topbar">
        <div class="brand">
            <div class="logo">IR</div>
            <div>
                <h1>InventoryRite</h1>
                <p>Simple Clover inventory, pricing, and product updates</p>
            </div>
        </div>

        <div class="badge ${connected ? "connected" : "disconnected"}" id="topBadge">
            ${connected ? "Connected" : "Connection Required"}
        </div>
    </div>

    <main class="wrap">

        ${connected ? `
        <section class="hero simple-hero">
            <div class="simple-hero-copy">
                <div class="eyebrow">Clover Inventory</div>
                <h2>Manage products without the clutter.</h2>
                <p>Search, edit prices, add products, and sync Clover from one clean inventory screen. Advanced tools are still here when you need them.</p>
            </div>
            <div class="simple-hero-actions">
                <button id="btnHeroAdd" type="button" class="btn btn-primary">Add Product</button>
                <button id="btnHeroSync" type="button" class="btn btn-light">Sync Clover</button>
                <button id="btnHeroAdvanced" type="button" class="btn btn-light">Advanced Tools</button>
            </div>
        </section>

        
<section class="card inventory-card">

            <div class="operations-summary-strip simple-status-strip">
                <div class="operations-summary-main">
                    <strong>Ready to work</strong>
                    <span>Start with search, add product, or sync Clover. Extra review tools are tucked under Advanced Tools.</span>
                </div>
                <div class="operations-summary-pills">
                    <div class="summary-pill" id="marginHealthStatus">Connected</div>
                    <div class="summary-pill">Live Clover Sync</div>
                </div>
            </div>

            <div class="table-top">
                <div>
                    <h3>Products</h3>
                    <p>Your Clover products appear below. Search, edit, save, or select rows for bulk updates.</p>
                    <div class="sync-note" id="lastSyncNote">Last synced: Not yet</div>
                </div>
            </div>

            <div class="inventory-command-center">
                <div class="command-center-top">
                    <div class="command-copy">
                        <div class="command-title">Start Here</div>
                        <div class="command-subtitle">Search first. Use Advanced Tools only when you need more options.</div>
                    </div>

                    <div class="command-search-actions">
                        <input id="inventorySearch" class="search-input" type="text" placeholder="Search products..." />
                        <button id="btnRefreshInventoryTop" type="button" class="btn btn-light">Sync Clover</button>
                        <button id="btnToggleAddTop" type="button" class="btn btn-primary">Add Product</button>
                        <button id="btnToggleBulkTop" type="button" class="btn btn-light">Bulk Update</button>
                        <button id="btnToggleAdvancedTop" type="button" class="btn btn-light">Advanced Tools</button>
                    </div>
                </div>
            </div>

            <!-- ADD PRODUCT PANEL -->
            <div class="add-panel" id="addPanel">
                <div class="add-panel-header">
                    <div>
                        <div class="add-panel-title">Add New Clover Product</div>
                        <div class="add-panel-subtitle">Enter the item name and price, then create it directly in Clover.</div>
                    </div>
                </div>
                <div class="add-grid">
                    <div>
                        <label for="itemName">Product Name</label>
                        <input id="itemName" type="text" value="New Clover Item" />
                    </div>
                    <div>
                        <label for="itemPrice">Price Cents</label>
                        <input id="itemPrice" type="number" value="199" />
                    </div>
                    <button id="btnCreateItem" type="button" class="btn btn-primary">Create</button>
                </div>
            </div>

            <!-- BULK PRICE UPDATE PANEL -->
            <div class="bulk-panel" id="bulkPanel">
                <div class="bulk-panel-header">
                    <div class="bulk-panel-title">
                        &#9889; Bulk Price Update &mdash;
                        <span id="bulkSelectedCount" class="bulk-count-badge">0</span>
                        item(s) selected
                    </div>
                    <div class="bulk-controls">
                        <div>
                            <label for="bulkPct" style="color:#92400e;">% Amount</label>
                            <input
                                id="bulkPct"
                                type="number"
                                class="bulk-pct-input"
                                value="10"
                                min="0.01"
                                max="9999"
                                step="0.01"
                                placeholder="10"
                            />
                        </div>
                        <div style="display:flex;gap:8px;align-items:flex-end;padding-bottom:0;">
                            <button id="btnBulkIncrease" type="button" class="btn btn-small btn-bulk-increase">
                                &#9650; Increase by %
                            </button>
                            <button id="btnBulkDecrease" type="button" class="btn btn-small btn-bulk-decrease">
                                &#9660; Decrease by %
                            </button>
                            <button id="btnBulkClearPanel" type="button" class="btn btn-small btn-light">
                                Clear Selection
                            </button>
                        </div>
                    </div>
                </div>
                <div class="margin-preset-row">
                    <div class="margin-preset-copy">Quick margin presets use the saved Cost field to calculate new selling prices for selected products.</div>
                    <div class="margin-preset-actions">
                        <button type="button" class="preset-btn" data-margin-preset="35">35%</button>
                        <button type="button" class="preset-btn" data-margin-preset="40">40%</button>
                        <button type="button" class="preset-btn" data-margin-preset="45">45%</button>
                        <button type="button" class="preset-btn" data-margin-preset="50">50%</button>
                    </div>
                </div>
                <div class="protected-pricing-note">Protected Pricing: InventoryRite never changes Clover prices without confirmation. You can review the selected count before every bulk update.</div>
                <div class="bulk-progress" id="bulkProgress">
                    <div class="bulk-progress-bar" id="bulkProgressBar"></div>
                </div>
                <div class="bulk-progress-label" id="bulkProgressLabel"></div>
            </div>



            <div class="merchant-control-bar" id="merchantControlBar">
                <div class="merchant-control-left">
                    <div class="merchant-control-title">Merchant Tools</div>
                    <div class="merchant-control-subtitle">Filters, reorder planning, safety backup export, price checks, cleanup, and action history in one place.</div>
                </div>
                <div class="merchant-control-actions">
                    <button id="btnShowAllProducts" type="button" class="control-btn control-neutral">All Products</button>
                    <button id="btnLowStock" type="button" class="control-btn control-neutral">Low Stock</button>
                    <button id="btnReorder" type="button" class="control-btn control-neutral">Reorder</button>
                    <button id="btnExportCsv" type="button" class="control-btn control-neutral">Export Safety Backup</button>
                    <button id="btnImportCsv" type="button" class="control-btn control-import">Import CSV</button>
                    <button id="btnDuplicateReview" type="button" class="control-btn control-neutral">Duplicate Review</button>
                    <button id="btnMissingCostLock" type="button" class="control-btn control-neutral">Missing Costs</button>
                    <button id="btnSmart99" type="button" class="control-btn control-neutral">Smart .99</button>
                    <button id="btnUndoBulk" type="button" class="control-btn control-neutral">Undo Bulk</button>
                    <button id="btnPriceRules" type="button" class="control-btn control-neutral">Pricing Tools</button>
                    <button id="btnProfitAlerts" type="button" class="control-btn control-profit">Margin Alerts</button>
                    <button id="btnCleanupScan" type="button" class="control-btn control-neutral">Inventory Cleanup</button>
                    <button id="btnActivityLog" type="button" class="control-btn control-neutral">Activity Log</button>
                </div>
            </div>
            <div class="view-filter-note" id="viewFilterNote"></div>
            <div class="productivity-hub" id="productivityHub">
                <button id="btnProfitIntelligence" type="button" class="productivity-card" data-icon="↗">
                    <div class="productivity-kicker">Profit</div>
                    <div class="productivity-title">Profit Review</div>
                    <div class="productivity-copy">Review pricing performance, low margins, and missing costs quickly.</div>
                </button>
                <button id="btnBulkOperationsHub" type="button" class="productivity-card" data-icon="▦">
                    <div class="productivity-kicker">Bulk</div>
                    <div class="productivity-title">Bulk Tools</div>
                    <div class="productivity-copy">Select rows, update prices, export CSV, and move faster.</div>
                </button>
                <button id="btnSmartPricingHub" type="button" class="productivity-card" data-icon="%">
                    <div class="productivity-kicker">Pricing</div>
                    <div class="productivity-title">Pricing Tools</div>
                    <div class="productivity-copy">Pricing reviews, margin checks, and faster menu price updates.</div>
                </button>
                <button id="btnCleanupToolsHub" type="button" class="productivity-card" data-icon="✓">
                    <div class="productivity-kicker">Cleanup</div>
                    <div class="productivity-title">Inventory Cleanup</div>
                    <div class="productivity-copy">Review missing prices, duplicate products, weak costs, and inventory issues.</div>
                </button>
                <button id="btnShortcutHub" type="button" class="productivity-card" data-icon="⚡">
                    <div class="productivity-kicker">Speed</div>
                    <div class="productivity-title">Quick Actions</div>
                    <div class="productivity-copy">Common product actions merchants use every day.</div>
                </button>
            </div>

            <div class="operations-summary-strip" id="operationsSummaryStrip">
                <div class="operations-summary-main">
                    <strong>Inventory Snapshot</strong>
                    <span id="operationsSummaryText">Refresh Clover inventory to review pricing, costs, margins, and cleanup items.</span>
                </div>
                <div class="operations-summary-pills">
                    <span class="summary-pill" id="summaryAlertPill">0 alerts</span>
                    <span class="summary-pill" id="summaryBelowCostPill">0 below cost</span>
                    <span class="summary-pill" id="summaryAvgMarginPill">Avg margin --</span>
                    <span class="summary-pill" id="summaryOpportunityPill">$0 opportunity</span>
                </div>
            </div>

            <div class="last-action-strip" id="lastActionStrip">
                <strong>Last Action</strong>
                <span id="lastActionText">Ready. No recent actions yet.</span>
                <span id="lastSavedStatus" class="last-saved-status">No saves yet</span>
            </div>
            <div class="recent-sidebar" id="recentChangesPanel">
                <div class="recent-sidebar-top">
                    <div>
                        <div class="recent-sidebar-title">Recent Changes</div>
                        <div class="recent-sidebar-subtitle">Price edits, bulk updates, CSV imports, backup exports, and margin tools from this browser.</div>
                    </div>
                    <button id="btnOpenPriceHistory" type="button" class="btn btn-small btn-light">View History</button>
                </div>
                <div class="recent-list" id="recentChangesList">
                    <div class="recent-empty">No changes yet. Product edits, bulk updates, and CSV imports will appear here automatically.</div>
                </div>
            </div>
            <input id="csvImportInput" type="file" accept=".csv,text/csv" style="display:none;" />

            <div class="stats-row">
                <div class="stat-box">
                    <div class="stat-label">Loaded Products</div>
                    <div class="stat-value" id="statLoaded">0</div>
                </div>
                <div class="stat-box">
                    <div class="stat-label">Visible Products</div>
                    <div class="stat-value" id="statVisible">0</div>
                </div>
                <div class="stat-box">
                    <div class="stat-label">Available Products</div>
                    <div class="stat-value" id="statAvailable">0</div>
                </div>
                <div class="stat-box">
                    <div class="stat-label">Total Menu Value</div>
                    <div class="stat-value" id="statValue">$0.00</div>
                </div>
            </div>

            <div class="stats-row" id="marginStatsRow">
                <div class="stat-box">
                    <div class="stat-label">Average Margin</div>
                    <div class="stat-value" id="statAvgMargin">&mdash;</div>
                </div>
                <div class="stat-box">
                    <div class="stat-label">Best Margin Item</div>
                    <div class="stat-value" id="statBestMargin">&mdash;</div>
                </div>
                <div class="stat-box">
                    <div class="stat-label">Lowest Margin Item</div>
                    <div class="stat-value" id="statLowestMargin">&mdash;</div>
                </div>
                <div class="stat-box">
                    <div class="stat-label">Below Cost</div>
                    <div class="stat-value" id="statBelowCost">0</div>
                </div>
            </div>

            <div class="merchant-hint">Tip: Select multiple rows, open Bulk Price Update, then increase or decrease selected product prices in one action.</div>

            <div class="table-wrap">
                <table>
                    <colgroup>
                        <col class="check-col" />
                        <col class="name-col" />
                        <col class="money-col" />
                        <col class="money-col" />
                        <col class="metric-col" />
                        <col class="actions-col" />
                    </colgroup>
                    <thead>
                        <tr>
                            <th class="col-check">
                                <input type="checkbox" id="selectAllCheckbox" title="Select all visible" />
                            </th>
                            <th>Product</th>
                            <th>Price</th>
                            <th>Cost</th>
                            <th>Margin</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody id="itemsBody">
                        <tr>
                            <td colspan="6" class="empty">
                                <strong>Loading Clover inventory...</strong>
                                Your products will appear here in a moment.
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </section>
        ` : `
        <section class="card setup-card">
            <div class="eyebrow">Clover Inventory</div>
            <h2>Connect Clover to manage your products.</h2>
            <p>This app needs permission to read and update Clover inventory. After connecting, your products will load automatically.</p>
            <a class="btn btn-primary" href="/connect-clover">Connect Clover</a>
        </section>
        `}

        <div class="footer">
            InventoryRite for Clover - Process Rite Inc - <a class="dev-link" href="/support">Support</a> - <a class="dev-link" href="/privacy">Privacy</a> - <a class="dev-link" href="/terms">Terms</a><br />
            Built for Clover merchants using InventoryRite&trade; - Version 1.0
        </div>

    </main>

    <div class="toast-wrap" id="toastWrap"></div>

    <div class="modal-backdrop" id="confirmModal">
        <div class="modal">
            <h3 id="confirmTitle">Confirm Action</h3>
            <p id="confirmMessage">Are you sure?</p>
            <div class="modal-actions">
                <button id="confirmCancel" type="button" class="btn btn-light">Cancel</button>
                <button id="confirmYes" type="button" class="btn btn-danger">Yes, Continue</button>
            </div>
        </div>
    </div>

    <div class="modal-backdrop" id="detailsModal">
        <div class="modal">
            <h3 id="detailsTitle">Product Details</h3>
            <p>Extra Clover fields and margin details are kept here so the main product table stays clean with no left/right scroll.</p>
            <div class="detail-grid" id="detailsGrid"></div>
            <div class="modal-actions">
                <button id="detailsClose" type="button" class="btn btn-light">Close</button>
            </div>
        </div>
    </div>



    <div class="modal-backdrop" id="featureModal">
        <div class="modal modal-wide">
            <h3 id="featureTitle">Feature</h3>
            <p id="featureMessage">Details will appear here.</p>
            <div class="insight-list" id="featureList"></div>
            <div class="modal-actions">
                <button id="featureClose" type="button" class="btn btn-light">Close</button>
            </div>
        </div>
    </div>

    <script>
    (function () {
        window.addEventListener("error", function (event) {
            try {
                console.error("InventoryRite UI error:", event.message, event.error);
                var wrap = document.getElementById("toastWrap");
                if (wrap) {
                    var toast = document.createElement("div");
                    toast.className = "toast error";
                    toast.textContent = "UI error detected. Open DevTools Console for details.";
                    wrap.appendChild(toast);
                }
            } catch (e) {}
        });

        var embeddedConnection = {
            connected: ${connected ? "true" : "false"},
            merchant_id: ${JSON.stringify(merchantId)},
            employee_id: ${JSON.stringify(employeeId)},
            access_token: "",
            csrf_token: ${JSON.stringify(csrfToken)},
            connected_at: ${JSON.stringify(connectedAt)}
        };

        var loadedItems = [];
        var itemCosts = {};
        var lastUpdatedItemId = "";
        var bulkUpdatedItemIds = [];
        var isBusy = false;
        var pendingConfirmAction = null;
        var activeViewMode = "all";
        var activityLog = [];
        var priceChangeHistory = [];
        var lastBulkUndoSnapshot = null;
        var lastSavedAt = null;
        var currentUserLabel = embeddedConnection.employee_id ? ("Employee " + embeddedConnection.employee_id) : "Current Clover user";
        var HISTORY_STORAGE_KEY = "inventoryrite_price_history_" + (embeddedConnection.merchant_id || "demo");
        var UNDO_STORAGE_KEY = "inventoryrite_last_bulk_undo_" + (embeddedConnection.merchant_id || "demo");

        // Track selected item IDs for bulk operations
        var selectedItemIds = new Set();

        function byId(id) {
            return document.getElementById(id);
        }

        function bind(id, eventName, handler) {
            var el = byId(id);
            if (el) {
                el.addEventListener(eventName, handler);
            }
        }

        function getToken() {
            // Bearer tokens stay on the server. The browser never needs to see them.
            return "server";
        }

        function getMerchantId() {
            return embeddedConnection.merchant_id || "";
        }

        function formatCurrencyFromCents(cents) {
            var value = Number(cents || 0) / 100;
            return value.toLocaleString(undefined, { style: "currency", currency: "USD" });
        }

        function formatDateFromClover(value) {
            if (!value) return "-";
            try {
                return new Date(Number(value)).toLocaleString();
            } catch (e) {
                return "-";
            }
        }

        function showToast(message, type) {
            var wrap = byId("toastWrap");
            if (!wrap) return;

            var toast = document.createElement("div");
            toast.className = "toast " + (type || "info");
            toast.textContent = message;
            wrap.appendChild(toast);

            setTimeout(function () {
                if (toast && toast.parentNode) {
                    toast.parentNode.removeChild(toast);
                }
            }, 4200);
        }

        function logActivity(title, message, status) {
            var entry = {
                title: title || "Activity",
                message: message || "Action completed.",
                status: status || "Done",
                time: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
            };

            activityLog.unshift(entry);

            renderRecentChangesPanel();

            if (activityLog.length > 50) {
                activityLog = activityLog.slice(0, 50);
            }

            updateLastAction(entry);
        }

        function updateLastAction(entry) {
            var text = byId("lastActionText");
            if (!text || !entry) return;
            text.textContent = entry.title + " - " + entry.message + " - " + entry.time;
        }

        function markSavedNow() {
            lastSavedAt = new Date();
            updateLastSavedStatus();
        }

        function updateLastSavedStatus() {
            var el = byId("lastSavedStatus");
            if (!el) return;

            if (!lastSavedAt) {
                el.textContent = "No saves yet";
                el.classList.remove("synced");
                return;
            }

            el.classList.add("synced");

            var diffSeconds = Math.max(0, Math.floor((Date.now() - lastSavedAt.getTime()) / 1000));
            if (diffSeconds < 5) {
                el.textContent = "All changes synced";
            } else if (diffSeconds < 60) {
                el.textContent = "Last saved " + diffSeconds + " seconds ago";
            } else {
                var minutes = Math.floor(diffSeconds / 60);
                el.textContent = "Last saved " + minutes + " minute" + (minutes === 1 ? "" : "s") + " ago";
            }
        }


        function loadStoredHistory() {
            try {
                var saved = localStorage.getItem(HISTORY_STORAGE_KEY);
                priceChangeHistory = saved ? JSON.parse(saved) : [];
                if (!Array.isArray(priceChangeHistory)) priceChangeHistory = [];
            } catch (e) {
                priceChangeHistory = [];
            }

            try {
                var undoSaved = localStorage.getItem(UNDO_STORAGE_KEY);
                lastBulkUndoSnapshot = undoSaved ? JSON.parse(undoSaved) : null;
            } catch (e2) {
                lastBulkUndoSnapshot = null;
            }

            renderRecentChangesPanel();
        }

        function saveStoredHistory() {
            try {
                localStorage.setItem(HISTORY_STORAGE_KEY, JSON.stringify(priceChangeHistory.slice(0, 75)));
            } catch (e) {}
            try {
                if (lastBulkUndoSnapshot) {
                    localStorage.setItem(UNDO_STORAGE_KEY, JSON.stringify(lastBulkUndoSnapshot));
                } else {
                    localStorage.removeItem(UNDO_STORAGE_KEY);
                }
            } catch (e2) {}
        }

        function formatRelativeTime(timestamp) {
            var date = timestamp ? new Date(timestamp) : new Date();
            var diff = Math.max(0, Date.now() - date.getTime());
            var minutes = Math.floor(diff / 60000);
            if (minutes < 1) return "just now";
            if (minutes < 60) return minutes + " min ago";
            var hours = Math.floor(minutes / 60);
            if (hours < 24) return hours + " hr ago";
            var days = Math.floor(hours / 24);
            return days + " day" + (days === 1 ? "" : "s") + " ago";
        }

        function recordPriceChange(item, oldCents, newCents, source) {
            oldCents = Number(oldCents || 0);
            newCents = Number(newCents || 0);
            if (oldCents === newCents && source !== "create") return;

            var entry = {
                id: item && item.id ? item.id : "",
                name: item && item.name ? item.name : "Unnamed Product",
                oldCents: oldCents,
                newCents: newCents,
                source: source || "Price Update",
                user: currentUserLabel,
                timestamp: new Date().toISOString()
            };

            priceChangeHistory.unshift(entry);
            priceChangeHistory = priceChangeHistory.slice(0, 75);
            saveStoredHistory();
            markSavedNow();
            renderRecentChangesPanel();
        }

        function renderRecentChangesPanel() {
            var list = byId("recentChangesList");
            if (!list) return;

            var recent = priceChangeHistory.slice(0, 3);
            if (!recent.length && activityLog.length) {
                recent = activityLog.slice(0, 3).map(function (entry) {
                    return {
                        name: entry.title,
                        oldCents: 0,
                        newCents: 0,
                        source: entry.status,
                        user: currentUserLabel,
                        timestamp: new Date().toISOString(),
                        message: entry.message
                    };
                });
            }

            if (!recent.length) {
                list.innerHTML = '<div class="recent-empty">No changes yet. Product edits, bulk updates, and CSV imports will appear here automatically.</div>';
                return;
            }

            list.innerHTML = recent.map(function (entry) {
                var priceLine = entry.message || (formatCurrencyFromCents(entry.oldCents) + " → " + formatCurrencyFromCents(entry.newCents));
                return "<div class='recent-item'><strong>" + escapeHtml(entry.name || "Change") + "</strong><span>" + escapeHtml(priceLine) + "</span><span>" + escapeHtml(entry.source || "Updated") + " by " + escapeHtml(entry.user || currentUserLabel) + " - " + escapeHtml(formatRelativeTime(entry.timestamp)) + "</span></div>";
            }).join("");
        }

        function setStatText(id, value) {
            var el = byId(id);
            if (!el) return;
            value = String(value);
            if (el.textContent !== value) {
                el.textContent = value;
                el.classList.remove("stat-pop");
                void el.offsetWidth;
                el.classList.add("stat-pop");
            }
        }

        function setRowSaveState(itemId, state, text) {
            var badge = document.querySelector('[data-save-state="' + itemId + '"]');
            if (!badge) return;
            badge.className = "save-state " + (state || "");
            badge.textContent = text || "Ready";
        }

        function setButtonText(id, text) {
            var btn = byId(id);
            if (btn) btn.textContent = text;
        }

        function updateLastSyncNote() {
            var note = byId("lastSyncNote");
            if (!note) return;
            note.textContent = "Sync successful: " + new Date().toLocaleString();
        }

        function setButtonsDisabled(disabled) {
            // IMPORTANT: Do not globally disable the whole dashboard.
            // If Clover inventory takes long to load, globally disabling every button
            // makes the Merchant Control Bar feel broken. We keep the UI clickable
            // and rely on each action to validate what it needs.
            return;
        }

        function startBusy() {
            isBusy = true;
            setButtonsDisabled(true);
        }

        function stopBusy() {
            isBusy = false;
            setButtonsDisabled(false);
        }

        function requireConnection() {
            var token = getToken();
            var merchantId = getMerchantId();

            // Tokens stay server-side now. If merchantId is blank, the backend will
            // use the most recent saved Clover connection from memory/database.
            if (!token) {
                showToast("Please connect Clover first.", "error");
                return null;
            }

            return { merchantId: merchantId || "" };
        }

        function escapeHtml(value) {
            return String(value || "")
                .replaceAll("&", "&amp;")
                .replaceAll("<", "&lt;")
                .replaceAll(">", "&gt;")
                .replaceAll('"', "&quot;")
                .replaceAll("'", "&#039;");
        }

        function priceToCentsFromDollarsString(value) {
            var clean = String(value || "0").replace("$", "").replace(",", "").trim();
            var dollars = Number(clean);
            if (Number.isNaN(dollars) || dollars < 0) return null;
            return Math.round(dollars * 100);
        }

        function getCostCents(itemId) {
            return Number(itemCosts[itemId] || 0);
        }

        function calculateMargin(priceCents, costCents) {
            priceCents = Number(priceCents || 0);
            costCents = Number(costCents || 0);
            if (priceCents <= 0) return null;
            return ((priceCents - costCents) / priceCents) * 100;
        }

        function getMarginPill(priceCents, costCents) {
            var margin = calculateMargin(priceCents, costCents);
            if (margin === null) return '<span class="pill warn">No price</span>';
            if (margin < 0) return '<span class="pill bad">' + margin.toFixed(1) + '%</span>';
            if (margin < 30) return '<span class="pill warn">' + margin.toFixed(1) + '%</span>';
            return '<span class="pill good">' + margin.toFixed(1) + '%</span>';
        }

        function updateStats(items) {
            items = items || [];
            var loaded = items.length;
            var visible = items.filter(function (item) { return !item.hidden; }).length;
            var available = items.filter(function (item) { return item.available !== false; }).length;
            var totalCents = items.reduce(function (sum, item) {
                return sum + Number(item.price || 0);
            }, 0);

            var marginItems = items
                .filter(function (item) { return Number(item.price || 0) > 0 && getCostCents(item.id || "") > 0; })
                .map(function (item) {
                    var price = Number(item.price || 0);
                    var cost = getCostCents(item.id || "");
                    var margin = calculateMargin(price, cost);
                    return {
                        id: item.id || "",
                        name: item.name || "Unnamed Product",
                        price: price,
                        cost: cost,
                        margin: margin,
                        profit: price - cost
                    };
                });

            var belowCost = marginItems.filter(function (item) { return item.profit < 0; }).length;
            var avgMargin = marginItems.length
                ? marginItems.reduce(function (sum, item) { return sum + item.margin; }, 0) / marginItems.length
                : null;
            var best = marginItems.length ? marginItems.slice().sort(function (a, b) { return b.margin - a.margin; })[0] : null;
            var lowest = marginItems.length ? marginItems.slice().sort(function (a, b) { return a.margin - b.margin; })[0] : null;

            var statLoaded = byId("statLoaded");
            var statVisible = byId("statVisible");
            var statAvailable = byId("statAvailable");
            var statValue = byId("statValue");
            var statAvgMargin = byId("statAvgMargin");
            var statBestMargin = byId("statBestMargin");
            var statLowestMargin = byId("statLowestMargin");
            var statBelowCost = byId("statBelowCost");

            setStatText("statLoaded", loaded);
            setStatText("statVisible", visible);
            setStatText("statAvailable", available);
            setStatText("statValue", formatCurrencyFromCents(totalCents));
            setStatText("statAvgMargin", avgMargin === null ? "-" : avgMargin.toFixed(1) + "%");
            setStatText("statBestMargin", best ? best.name.substring(0, 18) + " - " + best.margin.toFixed(1) + "%" : "-");
            setStatText("statLowestMargin", lowest ? lowest.name.substring(0, 18) + " - " + lowest.margin.toFixed(1) + "%" : "-");
            setStatText("statBelowCost", belowCost);
            renderIntelligencePanel();
        }

        /*
        |------------------------------------------------------------------
        | BULK SELECTION HELPERS
        |------------------------------------------------------------------
        */

        function syncBulkUI() {
            var count = selectedItemIds.size;
            var countBadge = byId("bulkSelectedCount");
            var selectAll = byId("selectAllCheckbox");

            if (countBadge) countBadge.textContent = String(count);

            // Update select-all checkbox visual state
            if (selectAll) {
                var body = byId("itemsBody");
                var allCheckboxes = body ? body.querySelectorAll("input[type='checkbox'][data-item-id]") : [];
                var total = allCheckboxes.length;
                selectAll.indeterminate = count > 0 && count < total;
                selectAll.checked = total > 0 && count === total;
            }

            // Highlight selected rows
            var body = byId("itemsBody");
            if (body) {
                var rows = body.querySelectorAll("tr[data-row-id]");
                rows.forEach(function (row) {
                    var id = row.getAttribute("data-row-id");
                    if (selectedItemIds.has(id)) {
                        row.classList.add("row-selected");
                    } else {
                        row.classList.remove("row-selected");
                    }
                });
            }
        }

        function clearSelection() {
            selectedItemIds.clear();
            syncBulkUI();
        }

        function toggleItemSelection(itemId, checked) {
            if (checked) {
                selectedItemIds.add(itemId);
            } else {
                selectedItemIds.delete(itemId);
            }
            syncBulkUI();
        }

        function selectAllVisible(checked) {
            var body = byId("itemsBody");
            if (!body) return;
            var checkboxes = body.querySelectorAll("input[type='checkbox'][data-item-id]");
            checkboxes.forEach(function (cb) {
                var id = cb.getAttribute("data-item-id");
                if (checked) {
                    selectedItemIds.add(id);
                } else {
                    selectedItemIds.delete(id);
                }
                cb.checked = checked;
            });
            syncBulkUI();
        }

        /*
        |------------------------------------------------------------------
        | BULK PRICE UPDATE
        |------------------------------------------------------------------
        */

        async function runBulkPriceUpdate(direction) {
            if (isBusy) return;

            var connection = requireConnection();
            if (!connection) return;

            if (selectedItemIds.size === 0) {
                showToast("Select at least one product to bulk update.", "error");
                return;
            }

            var pctInput = byId("bulkPct");
            var pct = parseFloat(pctInput ? pctInput.value : "10");

            if (Number.isNaN(pct) || pct <= 0) {
                showToast("Enter a valid percentage greater than 0.", "error");
                if (pctInput) pctInput.focus();
                return;
            }

            var selectedIds = Array.from(selectedItemIds);
            var dirLabel = direction === "increase" ? "increased" : "decreased";
            var dirWord = direction === "increase" ? "Increasing" : "Decreasing";

            openConfirm(
                "Bulk Price " + (direction === "increase" ? "Increase" : "Decrease"),
                "You are about to update " + selectedIds.length + " live Clover product price(s) by " + (direction === "increase" ? "+" : "-") + pct + "%. Please confirm before InventoryRite saves these changes. You can use Undo Bulk immediately after this if needed.",
                async function () {
                    await executeBulkUpdate(connection, selectedIds, pct, direction, dirLabel);
                }
            );
        }

        async function executeBulkUpdate(connection, selectedIds, pct, direction, dirLabel) {
            startBusy();

            var progressWrap = byId("bulkProgress");
            var progressBar = byId("bulkProgressBar");
            var progressLabel = byId("bulkProgressLabel");

            if (progressWrap) progressWrap.classList.add("show");
            if (progressLabel) progressLabel.classList.add("show");

            var total = selectedIds.length;
            var successCount = 0;
            var failCount = 0;
            var undoSnapshot = {
                source: "Bulk Price Update",
                direction: direction,
                pct: pct,
                timestamp: new Date().toISOString(),
                items: []
            };

            bulkUpdatedItemIds = [];

            for (var i = 0; i < total; i++) {
                var itemId = selectedIds[i];
                var item = loadedItems.find(function (it) { return it.id === itemId; });

                if (!item) {
                    failCount++;
                    continue;
                }

                var currentCents = Number(item.price || 0);
                var multiplier = direction === "increase"
                    ? (1 + pct / 100)
                    : (1 - pct / 100);

                var newCents = Math.max(0, Math.round(currentCents * multiplier));

                // Progress
                var pctDone = Math.round(((i) / total) * 100);
                if (progressBar) progressBar.style.width = pctDone + "%";
                if (progressLabel) progressLabel.textContent = "Updating " + (i + 1) + " of " + total + ": " + escapeHtml(item.name || itemId);

                try {
                    await fetchJson(
                        "/clover-update-item/" + encodeURIComponent(itemId),
                        {
                            method: "POST",
                            headers: { "Content-Type": "application/json" },
                            body: JSON.stringify({ name: item.name || "", price: newCents })
                        }
                    );
                    successCount++;
                    undoSnapshot.items.push({ id: itemId, name: item.name || "Unnamed Product", oldCents: currentCents, newCents: newCents });
                    recordPriceChange(item, currentCents, newCents, "Bulk Price Update");
                    bulkUpdatedItemIds.push(itemId);
                } catch (err) {
                    failCount++;
                    console.error("Bulk update failed for item", itemId, err);
                }
            }

            // Complete progress
            if (progressBar) progressBar.style.width = "100%";
            if (progressLabel) progressLabel.textContent = "Done! " + successCount + " updated, " + failCount + " failed.";

            setTimeout(function () {
                if (progressWrap) progressWrap.classList.remove("show");
                if (progressLabel) progressLabel.classList.remove("show");
                if (progressBar) progressBar.style.width = "0%";
            }, 2400);

            if (undoSnapshot.items.length > 0) {
                lastBulkUndoSnapshot = undoSnapshot;
                saveStoredHistory();
            }

            if (failCount === 0) {
                showToast("Bulk update complete: " + successCount + " price(s) " + dirLabel + " by " + pct + "%.", "success");
                logActivity("Bulk Price Update", successCount + " price(s) " + dirLabel + " by " + pct + "%.", "Success");
            } else {
                showToast("Bulk update: " + successCount + " succeeded, " + failCount + " failed.", failCount > 0 && successCount === 0 ? "error" : "info");
            }

            clearSelection();
            stopBusy();
            await loadItems();
        }



        /*
        |------------------------------------------------------------------
        | MERCHANT CONTROL BAR FEATURES
        |------------------------------------------------------------------
        */

        function getItemSku(item) {
            return item.sku || item.code || item.productCode || "";
        }

        function getItemQuantity(item) {
            var candidates = [item.stockCount, item.quantity, item.qty, item.inventoryCount, item.availableQuantity];
            for (var i = 0; i < candidates.length; i++) {
                if (candidates[i] !== undefined && candidates[i] !== null && candidates[i] !== "") {
                    var n = Number(candidates[i]);
                    if (!Number.isNaN(n) && Number.isFinite(n)) return n;
                }
            }
            return null;
        }

        function getLowStockItems() {
            return (loadedItems || []).filter(function (item) {
                var qty = getItemQuantity(item);
                return qty !== null && qty <= 5;
            });
        }

        function getProfitAlertItems() {
            return (loadedItems || []).filter(function (item) {
                var price = Number(item.price || 0);
                var cost = getCostCents(item.id || "");
                var margin = calculateMargin(price, cost);
                return price > 0 && cost > 0 && (price < cost || (margin !== null && margin < 30));
            });
        }

        function setViewMode(mode) {
            activeViewMode = mode || "all";
            var note = byId("viewFilterNote");
            if (note) {
                if (activeViewMode === "lowStock") {
                    note.textContent = "Showing Low Stock view. Products with quantity 5 or less appear here when Clover sends quantity data.";
                    note.classList.add("show");
                } else if (activeViewMode === "profitAlerts") {
                    note.textContent = "Showing Margin Alerts view. Low-margin and below-cost items are highlighted here.";
                    note.classList.add("show");
                } else if (activeViewMode === "cleanup") {
                    note.textContent = "Showing Inventory Cleanup view. Products with missing price, missing cost, duplicate names, bad names, missing SKU, or below-cost risk appear here.";
                    note.classList.add("show");
                } else if (activeViewMode === "missingCost") {
                    note.textContent = "Showing Missing Costs view. Products with no saved cost are highlighted so margin reviews become accurate.";
                    note.classList.add("show");
                } else if (activeViewMode === "duplicates") {
                    note.textContent = "Showing Duplicate Review view. Products with similar names are grouped for cleanup.";
                    note.classList.add("show");
                } else {
                    note.textContent = "";
                    note.classList.remove("show");
                }
            }
            renderItems(loadedItems);
        }

        function csvEscape(value) {
            var text = String(value === undefined || value === null ? "" : value);
            if (text.indexOf('"') >= 0 || text.indexOf(',') >= 0 || text.indexOf('\\n') >= 0 || text.indexOf('\\r') >= 0) {
                return '"' + text.replaceAll('"', '""') + '"';
            }
            return text;
        }

        function exportProductsCsv() {
            if (!loadedItems || loadedItems.length === 0) {
                showToast("Load inventory before exporting CSV.", "error");
                return;
            }

            var rows = [];
            rows.push(["Clover ID", "Product Name", "SKU", "Price", "Cost", "Margin %", "Profit Per Unit", "Available", "Hidden"].join(","));

            loadedItems.forEach(function (item) {
                var price = Number(item.price || 0);
                var cost = getCostCents(item.id || "");
                var margin = calculateMargin(price, cost);
                var profit = price - cost;
                rows.push([
                    csvEscape(item.id || ""),
                    csvEscape(item.name || ""),
                    csvEscape(getItemSku(item)),
                    csvEscape((price / 100).toFixed(2)),
                    csvEscape((cost / 100).toFixed(2)),
                    csvEscape(margin === null ? "" : margin.toFixed(1)),
                    csvEscape((profit / 100).toFixed(2)),
                    csvEscape(item.available === false ? "No" : "Yes"),
                    csvEscape(item.hidden ? "Yes" : "No")
                ].join(","));
            });

            var blob = new Blob([rows.join("\\n")], { type: "text/csv;charset=utf-8;" });
            var url = URL.createObjectURL(blob);
            var link = document.createElement("a");
            link.href = url;
            link.download = "inventoryrite-clover-products.csv";
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            URL.revokeObjectURL(url);
            showToast("CSV exported successfully.", "success");
            logActivity("CSV Exported", loadedItems.length + " product(s) exported.", "Success");
        }

        function openFeatureModal(title, message, rows) {
            var modal = byId("featureModal");
            var titleEl = byId("featureTitle");
            var messageEl = byId("featureMessage");
            var listEl = byId("featureList");

            if (titleEl) titleEl.textContent = title || "Feature";
            if (messageEl) messageEl.textContent = message || "";
            if (listEl) {
                listEl.innerHTML = "";
                (rows || []).forEach(function (row) {
                    var div = document.createElement("div");
                    div.className = "insight-row";
                    div.innerHTML = row;
                    listEl.appendChild(div);
                });
            }
            if (modal) modal.classList.add("show");
        }

        function closeFeatureModal() {
            var modal = byId("featureModal");
            if (modal) modal.classList.remove("show");
        }

        function showLowStock() {
            var lowItems = getLowStockItems();
            var rows = lowItems.slice(0, 25).map(function (item) {
                var qty = getItemQuantity(item);
                return "<div><strong>" + escapeHtml(item.name || "Unnamed Product") + "</strong><span>Quantity: " + escapeHtml(qty === null ? "Unknown" : qty) + " - Price " + escapeHtml(formatCurrencyFromCents(item.price || 0)) + "</span></div><div><span>Low Stock</span></div>";
            });

            openFeatureModal(
                "Low Stock",
                lowItems.length ? (lowItems.length + " low-stock item(s) found and shown in the table.") : "No low-stock items were found. Clover may not be sending quantity data for these products yet.",
                rows
            );
            setViewMode("lowStock");
            logActivity("Low Stock View", lowItems.length + " low-stock item(s) reviewed.", "Viewed");
            showToast("Low Stock view enabled.", "info");
        }

        function showProfitAlerts() {
            var alerts = getProfitAlertItems();
            var rows = alerts.slice(0, 25).map(function (item) {
                var price = Number(item.price || 0);
                var cost = getCostCents(item.id || "");
                var margin = calculateMargin(price, cost);
                var label = price < cost ? "Below Cost" : "Low Margin";
                return "<div><strong>" + escapeHtml(item.name || "Unnamed Product") + "</strong><span>Price " + escapeHtml(formatCurrencyFromCents(price)) + " - Cost " + escapeHtml(formatCurrencyFromCents(cost)) + " - Margin " + escapeHtml(margin === null ? "-" : margin.toFixed(1) + "%") + "</span></div><div><span>" + escapeHtml(label) + "</span></div>";
            });

            openFeatureModal(
                "Margin Alerts",
                alerts.length ? (alerts.length + " product(s) need margin review and are now shown in the table.") : "No margin alerts right now. No below-cost or low-margin products were found.",
                rows
            );
            setViewMode("profitAlerts");
            logActivity("Margin Alerts", alerts.length + " product(s) reviewed for margin risk.", "Viewed");
            showToast("Margin Alerts view enabled.", alerts.length ? "info" : "success");
        }

        function showReorderPlanning() {
            var lowItems = getLowStockItems();
            var rows = lowItems.slice(0, 25).map(function (item) {
                var qty = getItemQuantity(item);
                return "<div><strong>" + escapeHtml(item.name || "Unnamed Product") + "</strong><span>Current quantity: " + escapeHtml(qty === null ? "Unknown" : qty) + " - Suggested action: reorder or confirm stock count</span></div><div><span>Plan</span></div>";
            });
            openFeatureModal(
                "Reorder Planning",
                lowItems.length ? "Reorder planning is based on products with quantity 5 or less." : "No reorder suggestions yet. This becomes stronger when Clover sends quantity data.",
                rows
            );
            logActivity("Reorder Planning", lowItems.length + " item(s) checked for reorder planning.", "Viewed");
            showToast("Reorder planning opened.", "info");
        }

        function showPriceRules() {
            var rows = [
                "<div><strong>Round Prices</strong><span>Use Bulk Price Update, then review prices ending in .99 before saving.</span></div><div><span>Manual</span></div>",
                "<div><strong>Protect Margin</strong><span>Use Margin Alerts to find products below 30% margin or below cost.</span></div><div><span>Active</span></div>",
                "<div><strong>Bulk Percent Change</strong><span>Select rows, open Bulk Price Update, then increase or decrease by a percent.</span></div><div><span>Active</span></div>"
            ];
            openFeatureModal(
                "Pricing Tools Rules",
                "Pricing Tools is staged as safe merchant guidance. No automatic price overwrite happens without confirmation.",
                rows
            );
            logActivity("Pricing Tools", "Price rule options reviewed.", "Viewed");
            showToast("Pricing Tools opened.", "info");
        }

        function showActivityLog() {
            var rows = activityLog.length ? activityLog.map(function (entry) {
                return "<div><strong>" + escapeHtml(entry.time + " - " + entry.title) + "</strong><span>" + escapeHtml(entry.message) + "</span></div><div><span>" + escapeHtml(entry.status) + "</span></div>";
            }) : [
                "<div><strong>No activity yet</strong><span>Updates, exports, filters, and bulk actions will appear here during this session.</span></div><div><span>Ready</span></div>"
            ];

            openFeatureModal(
                "Activity Log",
                "Recent actions from this browser session appear here. Server-side history can be added after launch.",
                rows
            );
        }


        function getDuplicateNameMap() {
            var map = {};
            (loadedItems || []).forEach(function (item) {
                var key = String(item.name || "").trim().toLowerCase();
                if (!key) return;
                if (!map[key]) map[key] = [];
                map[key].push(item);
            });
            return map;
        }

        function getCleanupIssues() {
            var duplicateMap = getDuplicateNameMap();
            var issues = [];

            (loadedItems || []).forEach(function (item) {
                var name = String(item.name || "").trim();
                var price = Number(item.price || 0);
                var cost = getCostCents(item.id || "");
                var sku = getItemSku(item);
                var duplicateCount = name ? ((duplicateMap[name.toLowerCase()] || []).length) : 0;

                if (!name || name.toLowerCase() === "new clover item") {
                    issues.push({ item: item, type: "Bad Name", message: "Product name is missing or still using a default placeholder." });
                }
                if (price <= 0) {
                    issues.push({ item: item, type: "Missing Price", message: "Product has no sell price. This can cause checkout mistakes." });
                }
                if (cost <= 0) {
                    issues.push({ item: item, type: "Missing Cost", message: "No cost entered, so margin and margin review are incomplete." });
                }
                if (price > 0 && cost > 0 && price < cost) {
                    issues.push({ item: item, type: "Below Cost", message: "Sell price is lower than cost. This product may lose money." });
                }
                if (duplicateCount > 1) {
                    issues.push({ item: item, type: "Duplicate Name", message: "Another Clover product has the same name. Review duplicates before editing." });
                }
                if (!sku) {
                    issues.push({ item: item, type: "Missing SKU", message: "No SKU/code detected. Searching and auditing may be harder." });
                }
            });

            return issues;
        }

        function getProfitSummary() {
            var priced = 0;
            var costed = 0;
            var belowCost = 0;
            var lowMargin = 0;
            var missingCost = 0;
            var missingPrice = 0;
            var totalProfitCents = 0;
            var marginSum = 0;
            var marginCount = 0;

            (loadedItems || []).forEach(function (item) {
                var price = Number(item.price || 0);
                var cost = getCostCents(item.id || "");
                if (price > 0) priced++;
                if (cost > 0) costed++;
                if (price <= 0) missingPrice++;
                if (cost <= 0) missingCost++;
                if (price > 0 && cost > 0) {
                    var margin = calculateMargin(price, cost);
                    totalProfitCents += (price - cost);
                    marginSum += margin;
                    marginCount++;
                    if (price < cost) belowCost++;
                    if (margin !== null && margin < 30) lowMargin++;
                }
            });

            return {
                priced: priced,
                costed: costed,
                belowCost: belowCost,
                lowMargin: lowMargin,
                missingCost: missingCost,
                missingPrice: missingPrice,
                avgMargin: marginCount ? (marginSum / marginCount) : null,
                totalProfitCents: totalProfitCents,
                marginCount: marginCount
            };
        }

        function showProfitIntelligence() {
            var summary = getProfitSummary();
            var alerts = getProfitAlertItems();
            var rows = [];

            rows.push("<div><strong>Average Margin</strong><span>" + escapeHtml(summary.avgMargin === null ? "Add costs to calculate average margin." : summary.avgMargin.toFixed(1) + "% across " + summary.marginCount + " costed item(s).") + "</span></div><div><span>Profit</span></div>");
            rows.push("<div><strong>Below Cost</strong><span>" + escapeHtml(summary.belowCost + " product(s) are priced below cost.") + "</span></div><div><span>Risk</span></div>");
            rows.push("<div><strong>Missing Cost</strong><span>" + escapeHtml(summary.missingCost + " product(s) need cost entered before profit is accurate.") + "</span></div><div><span>Fix</span></div>");
            rows.push("<div><strong>Missing Price</strong><span>" + escapeHtml(summary.missingPrice + " product(s) have no sell price.") + "</span></div><div><span>Fix</span></div>");

            alerts.slice(0, 12).forEach(function (item) {
                var price = Number(item.price || 0);
                var cost = getCostCents(item.id || "");
                var margin = calculateMargin(price, cost);
                rows.push("<div><strong>" + escapeHtml(item.name || "Unnamed Product") + "</strong><span>Price " + escapeHtml(formatCurrencyFromCents(price)) + " - Cost " + escapeHtml(formatCurrencyFromCents(cost)) + " - Margin " + escapeHtml(margin === null ? "-" : margin.toFixed(1) + "%") + "</span></div><div><span>Review</span></div>");
            });

            openFeatureModal(
                "Profit Review",
                "This shows what needs attention before a merchant loses money: below-cost items, weak margins, missing costs, and missing prices.",
                rows
            );
            logActivity("Profit Review", "Profit risks reviewed.", "Viewed");
            showToast("Profit Review opened.", "info");
        }

        function showBulkOperationsHub() {
            var rows = [
                "<div><strong>Bulk Price Update</strong><span>Select products in the table, open Bulk Update, then increase or decrease selected items by a percentage.</span></div><div><span>Active</span></div>",
                "<div><strong>CSV Export</strong><span>Export the full product list with price, cost, margin, profit, availability, and hidden status.</span></div><div><span>Active</span></div>",
                "<div><strong>Filtered Views</strong><span>Use Low Stock or Margin Alerts before selecting rows so bulk actions are safer.</span></div><div><span>Active</span></div>",
                "<div><strong>Selection Count</strong><span>Selected products: " + escapeHtml(selectedItemIds.size) + ".</span></div><div><span>Ready</span></div>"
            ];
            openFeatureModal("Bulk Tools", "These are the fast merchant workflows that make this more than Clover's default inventory screen.", rows);
            logActivity("Bulk Tools", "Bulk workflow guide opened.", "Viewed");
            showToast("Bulk Tools opened.", "info");
        }

        function getSmartPriceSuggestion(item) {
            var price = Number(item.price || 0);
            var cost = getCostCents(item.id || "");
            if (price <= 0 && cost > 0) return { label: "Set Price", text: "Suggested starting price at 40% margin: " + formatCurrencyFromCents(Math.ceil(cost / 0.60)) };
            if (price > 0 && cost > 0) {
                var margin = calculateMargin(price, cost);
                if (price < cost) return { label: "Below Cost", text: "Suggested price at 40% margin: " + formatCurrencyFromCents(Math.ceil(cost / 0.60)) };
                if (margin !== null && margin < 30) return { label: "Low Margin", text: "Suggested price at 40% margin: " + formatCurrencyFromCents(Math.ceil(cost / 0.60)) };
            }
            if (price > 0) {
                var dollars = price / 100;
                var rounded99 = Math.max(0.99, Math.floor(dollars) + 0.99);
                if (Math.abs(rounded99 - dollars) > 0.001 && Math.abs(rounded99 - dollars) <= 1.00) {
                    return { label: ".99 Round", text: "Optional retail rounding idea: $" + rounded99.toFixed(2) };
                }
            }
            return { label: "Healthy", text: "No urgent smart pricing issue detected." };
        }

        function showSmartPricing() {
            var sourceItems = selectedItemIds.size
                ? (loadedItems || []).filter(function (item) { return selectedItemIds.has(item.id || ""); })
                : (loadedItems || []);

            var rows = sourceItems.slice(0, 25).map(function (item) {
                var suggestion = getSmartPriceSuggestion(item);
                return "<div><strong>" + escapeHtml(item.name || "Unnamed Product") + "</strong><span>Current price " + escapeHtml(formatCurrencyFromCents(item.price || 0)) + " - Cost " + escapeHtml(formatCurrencyFromCents(getCostCents(item.id || ""))) + " - " + escapeHtml(suggestion.text) + "</span></div><div><span>" + escapeHtml(suggestion.label) + "</span></div>";
            });

            if (!rows.length) {
                rows = ["<div><strong>No products loaded</strong><span>Refresh Clover inventory first, then Pricing Tools will suggest safe improvements.</span></div><div><span>Ready</span></div>"];
            }

            openFeatureModal(
                "Pricing Tools",
                selectedItemIds.size ? "Showing pricing ideas for selected products only. Suggestions are review-only and do not overwrite Clover automatically." : "Showing pricing ideas for the first products in your Clover list. Suggestions are review-only and do not overwrite Clover automatically.",
                rows
            );
            logActivity("Pricing Tools", "Smart pricing suggestions reviewed.", "Viewed");
            showToast("Pricing Tools opened.", "info");
        }

        function showCleanupTools() {
            var issues = getCleanupIssues();
            var rows = issues.slice(0, 35).map(function (issue) {
                return "<div><strong>" + escapeHtml(issue.item.name || "Unnamed Product") + " <span class='cleanup-tag'>" + escapeHtml(issue.type) + "</span></strong><span>" + escapeHtml(issue.message) + "</span></div><div><span>Fix</span></div>";
            });

            if (!rows.length) {
                rows = ["<div><strong>No cleanup issues found</strong><span>Your loaded products look clean based on name, price, cost, SKU, duplicate, and below-cost checks.</span></div><div><span>Clean</span></div>"];
            }

            openFeatureModal(
                "Inventory Cleanup",
                issues.length ? (issues.length + " cleanup issue(s) found. This is the merchant-friendly audit Clover should make easier.") : "No cleanup issues were found in the loaded product list.",
                rows
            );
            setViewMode("cleanup");
            logActivity("Inventory Cleanup", issues.length + " cleanup issue(s) reviewed.", "Viewed");
            showToast("Cleanup scan complete.", issues.length ? "info" : "success");
        }



        /*
        |------------------------------------------------------------------
        | MERCHANT INVENTORY HEALTH RULES - V1
        |------------------------------------------------------------------
        | This uses transparent merchant rules and plain-language explanations.
        | Every insight should answer: what is wrong, why it matters, and
        | what the merchant can do next.
        |------------------------------------------------------------------
        */

        function normalizeProductNameKey(value) {
            return String(value || "").toLowerCase().replace(/[^a-z0-9]+/g, " ").replace(/\s+/g, " ").trim();
        }

        function cleanProductName(value) {
            return String(value || "").replace(/\s+/g, " ").trim().replace(/\b\w/g, function (letter) { return letter.toUpperCase(); });
        }

        function getItemCategory(item) {
            if (!item) return "Uncategorized";
            if (item.category && item.category.name) return item.category.name;
            if (item.categories && item.categories.elements && item.categories.elements.length && item.categories.elements[0].name) return item.categories.elements[0].name;
            if (item.categories && Array.isArray(item.categories) && item.categories.length && item.categories[0].name) return item.categories[0].name;
            return "Uncategorized";
        }

        function getItemBarcode(item) {
            return item.barcode || item.upc || item.ean || item.code || "";
        }

        function getLastTouchedTime(item) {
            var candidates = [item.modifiedTime, item.createdTime, item.updatedTime, item.updateTime];
            for (var i = 0; i < candidates.length; i++) {
                var value = Number(candidates[i] || 0);
                if (value > 0) return value;
            }
            return 0;
        }

        function roundToRetail99(cents) {
            cents = Math.max(0, Math.round(Number(cents || 0)));
            if (cents <= 0) return 99;
            var dollars = cents / 100;
            var rounded = Math.max(0.99, Math.ceil(dollars) - 0.01);
            if (rounded * 100 < cents) rounded += 1;
            return Math.round(rounded * 100);
        }

        function getTargetPriceForMargin(costCents, targetMarginPercent) {
            costCents = Math.max(0, Number(costCents || 0));
            var marginDecimal = Math.max(1, Math.min(95, Number(targetMarginPercent || 40))) / 100;
            if (costCents <= 0) return 0;
            return roundToRetail99(Math.ceil(costCents / (1 - marginDecimal)));
        }

        function makeIssue(type, severity, item, title, explanation, recommendation, estimatedImpactCents, action) {
            return {
                type: type,
                severity: severity,
                item: item,
                itemId: item && item.id ? item.id : "",
                itemName: item && item.name ? item.name : "Unnamed Product",
                title: title,
                explanation: explanation,
                recommendation: recommendation,
                message: explanation + " " + recommendation,
                estimatedImpactCents: Number(estimatedImpactCents || 0),
                action: action || "review"
            };
        }

        function analyzeInventoryIntelligence(items) {
            items = items || [];
            var duplicateMap = {};
            var barcodeMap = {};
            var categoryBuckets = {};
            var issues = [];
            var safeAutoFixes = [];
            var estimatedMonthlyLoss = 0;
            var estimatedProfitOpportunity = 0;
            var penalty = 0;
            var assumedMonthlyUnits = 30;

            items.forEach(function (item) {
                var nameKey = normalizeProductNameKey(item.name || "");
                var barcodeKey = String(getItemBarcode(item) || "").trim();
                if (nameKey) {
                    if (!duplicateMap[nameKey]) duplicateMap[nameKey] = [];
                    duplicateMap[nameKey].push(item);
                }
                if (barcodeKey) {
                    if (!barcodeMap[barcodeKey]) barcodeMap[barcodeKey] = [];
                    barcodeMap[barcodeKey].push(item);
                }

                var category = getItemCategory(item);
                var price = Number(item.price || 0);
                var cost = getCostCents(item.id || "");
                if (!categoryBuckets[category]) categoryBuckets[category] = { name: category, count: 0, marginSum: 0, marginCount: 0, belowCost: 0, totalPrice: 0 };
                categoryBuckets[category].count++;
                categoryBuckets[category].totalPrice += price;
                if (price > 0 && cost > 0) {
                    var marginForCategory = calculateMargin(price, cost);
                    if (marginForCategory !== null) {
                        categoryBuckets[category].marginSum += marginForCategory;
                        categoryBuckets[category].marginCount++;
                    }
                    if (price < cost) categoryBuckets[category].belowCost++;
                }
            });

            var storeMarginSum = 0;
            var storeMarginCount = 0;
            items.forEach(function (item) {
                var price = Number(item.price || 0);
                var cost = getCostCents(item.id || "");
                if (price > 0 && cost > 0) {
                    var margin = calculateMargin(price, cost);
                    if (margin !== null) {
                        storeMarginSum += margin;
                        storeMarginCount++;
                    }
                }
            });
            var storeAvgMargin = storeMarginCount ? (storeMarginSum / storeMarginCount) : null;

            items.forEach(function (item) {
                var name = String(item.name || "").trim();
                var normalizedName = cleanProductName(name);
                var nameKey = normalizeProductNameKey(name);
                var price = Number(item.price || 0);
                var cost = getCostCents(item.id || "");
                var sku = getItemSku(item);
                var barcode = getItemBarcode(item);
                var category = getItemCategory(item);
                var margin = calculateMargin(price, cost);
                var duplicateNameCount = nameKey ? ((duplicateMap[nameKey] || []).length) : 0;
                var duplicateBarcodeCount = barcode ? ((barcodeMap[barcode] || []).length) : 0;
                var target40 = cost > 0 ? getTargetPriceForMargin(cost, 40) : 0;
                var target30 = cost > 0 ? getTargetPriceForMargin(cost, 30) : 0;
                var perUnitLoss = Math.max(0, cost - price);
                var perUnitOpportunity = target40 > price ? (target40 - price) : 0;
                var lastTouched = getLastTouchedTime(item);
                var staleDays = lastTouched ? Math.floor((Date.now() - lastTouched) / 86400000) : 0;

                if (!name || normalizeProductNameKey(name) === "new clover item") {
                    penalty += 6;
                    issues.push(makeIssue("bad_name", "warning", item, "Bad product name", "This product name is missing or still looks like a default placeholder.", "Rename it so reports, search, and staff checkout are easier to trust.", 0, "fix_name"));
                } else if (name !== normalizedName || /\s{2,}/.test(name)) {
                    penalty += 2;
                    issues.push(makeIssue("name_cleanup", "suggestion", item, "Name cleanup", "This product name has spacing or capitalization that can make inventory look messy.", "Suggested cleanup: " + normalizedName + ".", 0, "fix_name"));
                    safeAutoFixes.push({ item: item, type: "name_cleanup", value: normalizedName });
                }

                if (price <= 0) {
                    penalty += 15;
                    issues.push(makeIssue("missing_price", "critical", item, "Missing sell price", "This product has no sell price, which can create checkout mistakes and revenue leakage.", cost > 0 ? "Suggested starting price at 40% margin: " + formatCurrencyFromCents(target40) + "." : "Add a real selling price before using this product.", cost > 0 ? target40 * assumedMonthlyUnits : 0, "fix_price"));
                }

                if (cost <= 0) {
                    penalty += 8;
                    issues.push(makeIssue("missing_cost", "warning", item, "Missing true cost", "No cost is saved for this item, so margin and margin checks cannot be trusted yet.", "Enter the merchant true cost in the Cost field. This unlocks real margin alerts.", 0, "fix_cost"));
                }

                if (price > 0 && cost > 0 && price < cost) {
                    penalty += 18;
                    estimatedMonthlyLoss += perUnitLoss * assumedMonthlyUnits;
                    estimatedProfitOpportunity += perUnitOpportunity * assumedMonthlyUnits;
                    issues.push(makeIssue("below_cost", "critical", item, "Selling below cost", "This item is priced below cost and may lose about " + formatCurrencyFromCents(perUnitLoss) + " every sale.", "Suggested 40% margin price: " + formatCurrencyFromCents(target40) + ".", (perUnitLoss + perUnitOpportunity) * assumedMonthlyUnits, "fix_price"));
                } else if (price > 0 && cost > 0 && margin !== null && margin < 15) {
                    penalty += 10;
                    estimatedProfitOpportunity += perUnitOpportunity * assumedMonthlyUnits;
                    issues.push(makeIssue("weak_margin", "warning", item, "Weak margin", "This item margin is only " + margin.toFixed(1) + "%" + (storeAvgMargin !== null ? ", compared with your costed store average of " + storeAvgMargin.toFixed(1) + "%" : "") + ".", "Review pricing. Suggested 40% margin price: " + formatCurrencyFromCents(target40) + ".", perUnitOpportunity * assumedMonthlyUnits, "fix_price"));
                } else if (price > 0 && cost > 0 && margin !== null && margin < 30) {
                    penalty += 5;
                    estimatedProfitOpportunity += perUnitOpportunity * assumedMonthlyUnits;
                    issues.push(makeIssue("margin_opportunity", "opportunity", item, "Margin opportunity", "This item is profitable, but margin is " + margin.toFixed(1) + "% and may be weaker than the store target.", "Optional target: " + formatCurrencyFromCents(target40) + " for about 40% margin.", perUnitOpportunity * assumedMonthlyUnits, "fix_price"));
                }

                if (price > 0 && price <= 50) {
                    penalty += 7;
                    issues.push(makeIssue("suspicious_price", "critical", item, "Suspicious low price", "This product is priced at " + formatCurrencyFromCents(price) + ", which may be a cents/dollars mistake.", "Review the price before this item is sold accidentally too cheap.", 0, "fix_price"));
                }

                if (price >= 10000000) {
                    penalty += 7;
                    issues.push(makeIssue("suspicious_price", "warning", item, "Suspicious high price", "This product price is unusually high and may be a data-entry mistake.", "Review the price for extra zeros or decimal mistakes.", 0, "fix_price"));
                }

                if (duplicateNameCount > 1) {
                    penalty += 6;
                    issues.push(makeIssue("duplicate_name", "warning", item, "Duplicate product name", duplicateNameCount + " products appear to use the same normalized name. This can confuse reporting and staff searches.", "Review duplicates before editing or deleting. Keep the cleanest product record.", 0, "review"));
                }

                if (duplicateBarcodeCount > 1) {
                    penalty += 8;
                    issues.push(makeIssue("duplicate_barcode", "critical", item, "Duplicate barcode", duplicateBarcodeCount + " products appear to share the same barcode/code. This can cause scan mistakes.", "Review barcode duplicates before relying on scanning workflows.", 0, "review"));
                }

                if (!sku) {
                    penalty += 3;
                    issues.push(makeIssue("missing_sku", "suggestion", item, "Missing SKU", "No SKU or code was detected. Searching, auditing, and cleanup become harder over time.", "Use a consistent SKU format for this merchant, such as CAT-001 or ITEM-001.", 0, "review"));
                }

                if (category === "Uncategorized") {
                    penalty += 4;
                    issues.push(makeIssue("missing_category", "suggestion", item, "Missing category", "This product does not appear to have a category in the loaded Clover data.", "Assign categories so margin comparisons and cleanup insights become more useful.", 0, "review"));
                }

                if (staleDays >= 365) {
                    penalty += 5;
                    issues.push(makeIssue("stale_product", "warning", item, "Stale product", "This item has not been modified in about " + staleDays + " days based on Clover timestamps.", "Review old pricing and cost. Stale records are often underpriced or outdated.", 0, "review"));
                }
            });

            var categoryInsights = [];
            Object.keys(categoryBuckets).forEach(function (key) {
                var bucket = categoryBuckets[key];
                if (bucket.marginCount > 0) {
                    bucket.avgMargin = bucket.marginSum / bucket.marginCount;
                    categoryInsights.push(bucket);
                }
            });
            categoryInsights.sort(function (a, b) { return a.avgMargin - b.avgMargin; });

            var criticalIssues = issues.filter(function (issue) { return issue.severity === "critical"; });
            var warnings = issues.filter(function (issue) { return issue.severity === "warning"; });
            var opportunities = issues.filter(function (issue) { return issue.severity === "opportunity" || issue.severity === "suggestion"; });
            var healthScore = Math.max(0, Math.min(100, Math.round(100 - penalty)));

            return {
                healthScore: healthScore,
                criticalIssues: criticalIssues,
                warnings: warnings,
                opportunities: opportunities,
                allIssues: issues,
                estimatedMonthlyLoss: estimatedMonthlyLoss,
                estimatedProfitOpportunity: estimatedProfitOpportunity,
                storeAvgMargin: storeAvgMargin,
                categoryInsights: categoryInsights,
                safeAutoFixes: safeAutoFixes,
                assumedMonthlyUnits: assumedMonthlyUnits
            };
        }

        function getInventoryIntelligence() {
            return analyzeInventoryIntelligence(loadedItems || []);
        }

        function renderIntelligencePanel() {
            var intelligence = getInventoryIntelligence();
            var summaryText = byId("operationsSummaryText");
            var alertPill = byId("summaryAlertPill");
            var belowCostPill = byId("summaryBelowCostPill");
            var avgMarginPill = byId("summaryAvgMarginPill");
            var opportunityPill = byId("summaryOpportunityPill");

            var criticalCount = intelligence.criticalIssues.length;
            var warningCount = intelligence.warnings.length;
            var totalAlerts = criticalCount + warningCount;
            var belowCostCount = intelligence.criticalIssues.filter(function (issue) { return issue.type === "below_cost"; }).length;

            var marginItems = (loadedItems || [])
                .filter(function (item) { return Number(item.price || 0) > 0 && getCostCents(item.id || "") > 0; })
                .map(function (item) {
                    return calculateMargin(Number(item.price || 0), getCostCents(item.id || ""));
                })
                .filter(function (margin) { return margin !== null && Number.isFinite(margin); });

            var avgMargin = marginItems.length
                ? marginItems.reduce(function (sum, margin) { return sum + margin; }, 0) / marginItems.length
                : null;

            if (summaryText) {
                summaryText.textContent = (loadedItems || []).length
                    ? "Pricing, cost, margin, and cleanup summary for the currently loaded Clover products."
                    : "Refresh Clover inventory to review pricing, costs, margins, and cleanup items.";
            }
            if (alertPill) alertPill.textContent = totalAlerts + " alert" + (totalAlerts === 1 ? "" : "s");
            if (belowCostPill) belowCostPill.textContent = belowCostCount + " below cost";
            if (avgMarginPill) avgMarginPill.textContent = "Avg margin " + (avgMargin === null ? "--" : avgMargin.toFixed(1) + "%");
            if (opportunityPill) opportunityPill.textContent = formatCurrencyFromCents(intelligence.estimatedProfitOpportunity) + " opportunity";

            var health = byId("healthScoreText");
            var healthHelp = byId("healthScoreHelp");
            var critical = byId("criticalIssueText");
            var warning = byId("warningIssueText");
            var opportunity = byId("profitOpportunityText");
            var opportunityHelp = byId("profitOpportunityHelp");

            var displayHealthScore = Math.max(40, Number(intelligence.healthScore || 0));
            if (health) {
                health.textContent = displayHealthScore + "/100";
                health.className = "intelligence-value " + (displayHealthScore >= 85 ? "health-good" : (displayHealthScore >= 65 ? "health-watch" : "health-risk"));
            }
            if (healthHelp) healthHelp.textContent = displayHealthScore >= 85 ? "Inventory looks healthy. Keep reviewing costs and margins." : (displayHealthScore >= 65 ? "Inventory is usable, but cleanup and margin work can improve it." : "Inventory has review items. Start with missing costs, duplicate products, and margin checks.");
            if (critical) critical.textContent = criticalCount;
            if (warning) warning.textContent = warningCount;
            if (opportunity) opportunity.textContent = formatCurrencyFromCents(intelligence.estimatedProfitOpportunity);
            if (opportunityHelp) opportunityHelp.textContent = "Estimate assumes about " + intelligence.assumedMonthlyUnits + " sales/month on affected products until sales history is connected.";
        }

        function getCleanupIssues() {
            return getInventoryIntelligence().allIssues;
        }

        function getProfitSummary() {
            var intelligence = getInventoryIntelligence();
            var priced = 0;
            var costed = 0;
            var missingCost = 0;
            var missingPrice = 0;
            var totalProfitCents = 0;
            var marginSum = 0;
            var marginCount = 0;

            (loadedItems || []).forEach(function (item) {
                var price = Number(item.price || 0);
                var cost = getCostCents(item.id || "");
                if (price > 0) priced++;
                if (cost > 0) costed++;
                if (price <= 0) missingPrice++;
                if (cost <= 0) missingCost++;
                if (price > 0 && cost > 0) {
                    var margin = calculateMargin(price, cost);
                    totalProfitCents += (price - cost);
                    if (margin !== null) {
                        marginSum += margin;
                        marginCount++;
                    }
                }
            });

            return {
                priced: priced,
                costed: costed,
                belowCost: intelligence.criticalIssues.filter(function (issue) { return issue.type === "below_cost"; }).length,
                lowMargin: intelligence.warnings.filter(function (issue) { return issue.type === "weak_margin"; }).length,
                missingCost: missingCost,
                missingPrice: missingPrice,
                avgMargin: marginCount ? (marginSum / marginCount) : null,
                totalProfitCents: totalProfitCents,
                marginCount: marginCount,
                estimatedMonthlyLoss: intelligence.estimatedMonthlyLoss,
                estimatedProfitOpportunity: intelligence.estimatedProfitOpportunity,
                healthScore: intelligence.healthScore
            };
        }

        function severityBadge(severity) {
            return "<span class='severity-pill severity-" + escapeHtml(severity || "suggestion") + "'>" + escapeHtml(severity || "suggestion") + "</span>";
        }

        function getIssueActionButton(issue) {
            var label = "Review";
            if (issue.action === "fix_price") label = "Price";
            if (issue.action === "fix_cost") label = "Cost";
            if (issue.action === "fix_name") label = "Fix Name";
            return "<button type='button' class='insight-fix-btn' data-fix-action='" + escapeHtml(issue.action || "review") + "' data-fix-id='" + escapeHtml(issue.itemId || "") + "'>" + escapeHtml(label) + "</button>";
        }

        function issueToRow(issue) {
            var impact = issue.estimatedImpactCents > 0 ? " Estimated impact: " + formatCurrencyFromCents(issue.estimatedImpactCents) + "/month." : "";
            return "<div><strong>" + severityBadge(issue.severity) + escapeHtml(issue.itemName) + " <span class='cleanup-tag'>" + escapeHtml(issue.title) + "</span></strong><span>" + escapeHtml(issue.explanation + " " + issue.recommendation + impact) + "</span></div><div>" + getIssueActionButton(issue) + "</div>";
        }

        function showProfitIntelligence() {
            var summary = getProfitSummary();
            var intelligence = getInventoryIntelligence();
            var rows = [];

            rows.push("<div><strong>Product Review Score Score</strong><span>" + escapeHtml(summary.healthScore + "/100. This score drops when products are below cost, missing price, missing cost, duplicated, stale, or messy.") + "</span></div><div><span>Score</span></div>");
            rows.push("<div><strong>Estimated Monthly Loss</strong><span>" + escapeHtml(formatCurrencyFromCents(summary.estimatedMonthlyLoss) + " from below-cost products, using a conservative " + intelligence.assumedMonthlyUnits + " sales/month assumption until sales history is connected.") + "</span></div><div><span>Risk</span></div>");
            rows.push("<div><strong>Margin Opportunities</strong><span>" + escapeHtml(formatCurrencyFromCents(summary.estimatedProfitOpportunity) + " potential monthly improvement from pricing affected items toward a 40% margin target.") + "</span></div><div><span>Opportunity</span></div>");
            rows.push("<div><strong>Average Margin</strong><span>" + escapeHtml(summary.avgMargin === null ? "Add costs to calculate average margin." : summary.avgMargin.toFixed(1) + "% across " + summary.marginCount + " costed item(s).") + "</span></div><div><span>Profit</span></div>");
            intelligence.criticalIssues.concat(intelligence.warnings).slice(0, 14).forEach(function (issue) { rows.push(issueToRow(issue)); });
            if (intelligence.categoryInsights.length) {
                var weakest = intelligence.categoryInsights[0];
                rows.push("<div><strong>Weakest Category</strong><span>" + escapeHtml(weakest.name + " averages " + weakest.avgMargin.toFixed(1) + "% margin across " + weakest.marginCount + " costed item(s).") + "</span></div><div><span>Category</span></div>");
            }
            openFeatureModal("Profit Review", "Every result shows the risk, the reason, and the next step. Nothing changes in Clover until the merchant confirms it.", rows);
            logActivity("Profit Review", "Health " + summary.healthScore + "/100 with " + intelligence.criticalIssues.length + " critical issue(s).", "Viewed");
            showToast("Profit Review opened.", "info");
        }

        function getSmartPriceSuggestion(item) {
            var price = Number(item.price || 0);
            var cost = getCostCents(item.id || "");
            var target30 = cost > 0 ? getTargetPriceForMargin(cost, 30) : 0;
            var target40 = cost > 0 ? getTargetPriceForMargin(cost, 40) : 0;
            var target50 = cost > 0 ? getTargetPriceForMargin(cost, 50) : 0;
            var currentMargin = calculateMargin(price, cost);
            var rounded99 = price > 0 ? roundToRetail99(price) : 0;
            if (price <= 0 && cost > 0) return { label: "Set Price", text: "No selling price found. Suggested 40% margin price: " + formatCurrencyFromCents(target40) + ".", suggestedPrice: target40 };
            if (price > 0 && cost > 0 && price < cost) return { label: "Below Cost", text: "Current price loses " + formatCurrencyFromCents(cost - price) + " per sale. Suggested: " + formatCurrencyFromCents(target40) + " for about 40% margin.", suggestedPrice: target40 };
            if (price > 0 && cost > 0 && currentMargin !== null && currentMargin < 15) return { label: "Weak Margin", text: "Current margin is " + currentMargin.toFixed(1) + "%. Suggested: " + formatCurrencyFromCents(target40) + " for about 40% margin.", suggestedPrice: target40 };
            if (price > 0 && cost > 0 && currentMargin !== null && currentMargin < 30) return { label: "Opportunity", text: "Current margin is " + currentMargin.toFixed(1) + "%. 30% target: " + formatCurrencyFromCents(target30) + "; 40% target: " + formatCurrencyFromCents(target40) + ".", suggestedPrice: target40 };
            if (price > 0 && rounded99 > 0 && Math.abs(rounded99 - price) > 0 && Math.abs(rounded99 - price) <= 100) return { label: ".99 Round", text: "Optional retail rounding idea: " + formatCurrencyFromCents(rounded99) + ".", suggestedPrice: rounded99 };
            if (price > 0 && cost > 0) return { label: "Healthy", text: "Current margin is " + currentMargin.toFixed(1) + "%. 50% margin target would be " + formatCurrencyFromCents(target50) + ".", suggestedPrice: 0 };
            return { label: "Needs Cost", text: "Add cost first so pricing suggestions become meaningful.", suggestedPrice: 0 };
        }

        function showSmartPricing() {
            var sourceItems = selectedItemIds.size ? (loadedItems || []).filter(function (item) { return selectedItemIds.has(item.id || ""); }) : (loadedItems || []);
            var intelligence = getInventoryIntelligence();
            var priorityIds = intelligence.criticalIssues.concat(intelligence.warnings).filter(function (issue) { return issue.action === "fix_price"; }).map(function (issue) { return issue.itemId; });
            if (!selectedItemIds.size && priorityIds.length) {
                sourceItems = sourceItems.slice().sort(function (a, b) { return priorityIds.indexOf(b.id || "") - priorityIds.indexOf(a.id || ""); });
            }
            var rows = sourceItems.slice(0, 25).map(function (item) {
                var suggestion = getSmartPriceSuggestion(item);
                var button = suggestion.suggestedPrice > 0 ? "<button type='button' class='insight-fix-btn' data-fix-action='fix_price' data-fix-id='" + escapeHtml(item.id || "") + "'>Stage</button>" : "<span>Review</span>";
                return "<div><strong>" + escapeHtml(item.name || "Unnamed Product") + "</strong><span>Current price " + escapeHtml(formatCurrencyFromCents(item.price || 0)) + " - Cost " + escapeHtml(formatCurrencyFromCents(getCostCents(item.id || ""))) + " - " + escapeHtml(suggestion.text) + "</span></div><div>" + button + "</div>";
            });
            if (!rows.length) rows = ["<div><strong>No products loaded</strong><span>Refresh Clover inventory first, then Pricing Tools will suggest safe improvements.</span></div><div><span>Ready</span></div>"];
            openFeatureModal("Pricing Tools", selectedItemIds.size ? "Showing pricing ideas for selected products only. Suggestions stage values in the table and still require the checkmark save." : "Showing pricing ideas prioritized by risk. Suggestions stage values in the table and still require the checkmark save.", rows);
            logActivity("Pricing Tools", "Smart pricing suggestions reviewed.", "Viewed");
            showToast("Pricing Tools opened.", "info");
        }

        function showCleanupTools() {
            var intelligence = getInventoryIntelligence();
            var issues = intelligence.allIssues;
            var rows = [];
            rows.push("<div><strong>Product Review Score</strong><span>" + escapeHtml(intelligence.healthScore + "/100 with " + intelligence.criticalIssues.length + " critical issue(s), " + intelligence.warnings.length + " warning(s), and " + intelligence.opportunities.length + " opportunity/suggestion(s).") + "</span></div><div><span>Score</span></div>");
            issues.slice(0, 35).forEach(function (issue) { rows.push(issueToRow(issue)); });
            if (!issues.length) rows = ["<div><strong>No cleanup issues found</strong><span>Your loaded products look clean based on name, price, cost, SKU, duplicate, margin, category, stale, and suspicious-price checks.</span></div><div><span>Clean</span></div>"];
            openFeatureModal("Inventory Cleanup", issues.length ? (issues.length + " issue(s) found. Each issue explains the risk, recommendation, and where possible, a quick action.") : "No cleanup issues were found in the loaded product list.", rows);
            setViewMode("cleanup");
            logActivity("Inventory Cleanup", issues.length + " issue(s) reviewed. Health score " + intelligence.healthScore + "/100.", "Viewed");
            showToast("Cleanup scan complete.", issues.length ? "info" : "success");
        }

        function handleInsightFixAction(action, itemId) {
            var item = (loadedItems || []).find(function (x) { return (x.id || "") === itemId; });
            if (!item) { showToast("Product not found. Refresh inventory and try again.", "error"); return; }
            if (action === "fix_cost") {
                closeFeatureModal();
                setViewMode("all");
                setTimeout(function () {
                    var input = document.querySelector("[data-cost-for='" + itemId + "']");
                    if (input) { input.focus(); input.select(); showToast("Enter the true cost, then press Enter.", "info"); }
                    else showToast("Cost field is not visible. Search or show all products first.", "info");
                }, 150);
                return;
            }
            if (action === "fix_name") {
                var cleanName = cleanProductName(item.name || "");
                if (!cleanName || cleanName.toLowerCase() === "new clover item") { showToast("This name needs a real merchant decision. Rename it in the product row.", "info"); closeFeatureModal(); return; }
                closeFeatureModal();
                setViewMode("all");
                setTimeout(function () {
                    var nameInput = document.querySelector("[data-name-for='" + itemId + "']");
                    if (nameInput) { nameInput.value = cleanName; showToast("Cleaned name staged. Click the checkmark to save it to Clover.", "info"); nameInput.focus(); }
                }, 150);
                return;
            }
            if (action === "fix_price") {
                var suggestion = getSmartPriceSuggestion(item);
                if (!suggestion.suggestedPrice || suggestion.suggestedPrice <= 0) { showToast("Add cost first before applying smart price suggestions.", "info"); return; }
                closeFeatureModal();
                setViewMode("all");
                setTimeout(function () {
                    var priceInput = document.querySelector("[data-price-for='" + itemId + "']");
                    if (priceInput) { priceInput.value = (suggestion.suggestedPrice / 100).toFixed(2); showToast("Suggested price staged. Click the checkmark to save it to Clover.", "info"); priceInput.focus(); priceInput.select(); }
                }, 150);
                return;
            }
            showToast("Review this item in the table before making changes.", "info");
            closeFeatureModal();
            setViewMode("all");
        }

        function showOperationalShortcuts() {
            var rows = [
                "<div><strong>Fast Cost Entry</strong><span>Click any Cost cell, type the true cost, then press Enter. Margin updates after save.</span></div><div><span>Active</span></div>",
                "<div><strong>Profit Alert Filter</strong><span>Click Margin Alerts to focus only on products that may need a price fix.</span></div><div><span>Active</span></div>",
                "<div><strong>Inventory Cleanup</strong><span>Find duplicate names, missing prices, missing costs, bad names, and below-cost items.</span></div><div><span>Active</span></div>",
                "<div><strong>Export for Backup</strong><span>Use Export CSV before major edits so the merchant has a safe product snapshot.</span></div><div><span>Active</span></div>",
                "<div><strong>Safe Launch Rule</strong><span>No smart tool automatically changes Clover pricing without merchant confirmation.</span></div><div><span>Safe</span></div>"
            ];
            openFeatureModal("Quick Actions", "These are the daily shortcuts that make the app feel faster than Clover's normal product screen.", rows);
            logActivity("Quick Actions", "Shortcut guide opened.", "Viewed");
            showToast("Quick Actions opened.", "info");
        }


        function getDuplicateProductGroups() {
            var groups = {};
            (loadedItems || []).forEach(function (item) {
                var raw = String(item.name || "").toLowerCase();
                var key = raw
                    .replace(/[^a-z0-9 ]/g, " ")
                    .replace(/\b(oz|ounce|ounces|lb|lbs|pack|ct|count|small|medium|large|xl|bottle|can|bag)\b/g, " ")
                    .replace(/\b\d+(\.\d+)?\b/g, " ")
                    .replace(/\s+/g, " ")
                    .trim();
                if (!key || key.length < 3) return;
                if (!groups[key]) groups[key] = [];
                groups[key].push(item);
            });

            return Object.keys(groups).map(function (key) {
                return { key: key, items: groups[key] };
            }).filter(function (group) {
                return group.items.length > 1;
            }).sort(function (a, b) {
                return b.items.length - a.items.length;
            });
        }

        function getDuplicateProductIds() {
            var ids = {};
            getDuplicateProductGroups().forEach(function (group) {
                group.items.forEach(function (item) { ids[item.id || ""] = true; });
            });
            return ids;
        }

        function showDuplicateDetector() {
            var groups = getDuplicateProductGroups();
            var rows = [];
            groups.slice(0, 25).forEach(function (group) {
                rows.push("<div><strong>" + escapeHtml(group.key) + "</strong><span>" + escapeHtml(group.items.map(function (item) { return item.name || "Unnamed"; }).join(" | ")) + "</span></div><div><span>" + group.items.length + " similar</span></div>");
            });
            openFeatureModal(
                "Duplicate Product Review",
                groups.length ? (groups.length + " possible duplicate group(s) found. Review before editing or deleting products.") : "No obvious duplicate product groups were found.",
                rows
            );
            setViewMode("duplicates");
            logActivity("Duplicate Review", groups.length + " possible duplicate group(s) reviewed.", "Viewed");
            showToast("Duplicate review complete.", groups.length ? "info" : "success");
        }

        function showMissingCostLock() {
            var missing = (loadedItems || []).filter(function (item) { return getCostCents(item.id || "") <= 0; });
            var rows = missing.slice(0, 35).map(function (item) {
                return "<div><strong>" + escapeHtml(item.name || "Unnamed Product") + "</strong><span>Price " + escapeHtml(formatCurrencyFromCents(item.price || 0)) + " - Cost missing. Margin presets and margin review need a cost first.</span></div><div><span>Needs Cost</span></div>";
            });
            openFeatureModal(
                "Missing Cost Lock",
                missing.length ? (missing.length + " product(s) need a cost before margin tools can be trusted.") : "Every loaded product has a saved cost. Margin tools are ready.",
                rows
            );
            setViewMode("missingCost");
            logActivity("Missing Costs", missing.length + " product(s) checked for cost lock.", "Viewed");
            showToast("Missing Costs view enabled.", missing.length ? "info" : "success");
        }

        async function applyQuickMarginPreset(targetMarginPercent) {
            if (isBusy) return;
            var connection = requireConnection();
            if (!connection) return;
            if (selectedItemIds.size === 0) {
                showToast("Select products before applying a margin preset.", "error");
                return;
            }

            var selectedIds = Array.from(selectedItemIds);
            var ready = [];
            var skipped = 0;
            selectedIds.forEach(function (itemId) {
                var item = loadedItems.find(function (it) { return it.id === itemId; });
                var cost = getCostCents(itemId);
                if (!item || cost <= 0) { skipped++; return; }
                ready.push({ item: item, oldCents: Number(item.price || 0), newCents: getTargetPriceForMargin(cost, targetMarginPercent) });
            });

            if (!ready.length) {
                showToast("No selected products have saved costs. Add costs first.", "error");
                showMissingCostLock();
                return;
            }

            openConfirm(
                "Apply " + targetMarginPercent + "% Margin?",
                "This will calculate new selling prices for " + ready.length + " selected product(s) using saved costs" + (skipped ? ". " + skipped + " product(s) will be skipped because cost is missing." : "."),
                async function () {
                    await executeDirectPriceUpdates(connection, ready, targetMarginPercent + "% Margin Preset");
                }
            );
        }

        async function applySmart99Rounding() {
            if (isBusy) return;
            var connection = requireConnection();
            if (!connection) return;

            var sourceItems = selectedItemIds.size
                ? (loadedItems || []).filter(function (item) { return selectedItemIds.has(item.id || ""); })
                : (loadedItems || []);

            var ready = [];
            sourceItems.forEach(function (item) {
                var oldCents = Number(item.price || 0);
                var newCents = roundToRetail99(oldCents);
                if (oldCents > 0 && newCents !== oldCents) {
                    ready.push({ item: item, oldCents: oldCents, newCents: newCents });
                }
            });

            if (!ready.length) {
                showToast("No prices need .99 rounding in the selected/current list.", "success");
                return;
            }

            openConfirm(
                "Apply Smart .99 Rounding?",
                "This will round " + ready.length + " price(s) to clean retail .99 endings. Select rows first to limit the action, or run it on the visible inventory.",
                async function () {
                    await executeDirectPriceUpdates(connection, ready, "Smart .99 Rounding");
                }
            );
        }

        async function executeDirectPriceUpdates(connection, updateList, sourceLabel) {
            startBusy();
            var successCount = 0;
            var failCount = 0;
            var undoSnapshot = {
                source: sourceLabel,
                timestamp: new Date().toISOString(),
                items: []
            };

            for (var i = 0; i < updateList.length; i++) {
                var row = updateList[i];
                var item = row.item;
                try {
                    await fetchJson(
                        "/clover-update-item/" + encodeURIComponent(item.id || ""),
                        {
                            method: "POST",
                            headers: { "Content-Type": "application/json" },
                            body: JSON.stringify({ name: item.name || "", price: row.newCents })
                        }
                    );
                    successCount++;
                    undoSnapshot.items.push({ id: item.id || "", name: item.name || "Unnamed Product", oldCents: row.oldCents, newCents: row.newCents });
                    recordPriceChange(item, row.oldCents, row.newCents, sourceLabel);
                    bulkUpdatedItemIds.push(item.id || "");
                } catch (err) {
                    failCount++;
                    console.error(sourceLabel + " failed for item", item.id, err);
                }
            }

            if (undoSnapshot.items.length) {
                lastBulkUndoSnapshot = undoSnapshot;
                saveStoredHistory();
            }

            showToast(sourceLabel + ": " + successCount + " updated" + (failCount ? ", " + failCount + " failed." : "."), failCount && !successCount ? "error" : "success");
            logActivity(sourceLabel, successCount + " product(s) updated" + (failCount ? ", " + failCount + " failed." : "."), failCount ? "Partial" : "Success");
            clearSelection();
            stopBusy();
            await loadItems();
        }

        async function undoLastBulkUpdate() {
            if (isBusy) return;
            var connection = requireConnection();
            if (!connection) return;

            if (!lastBulkUndoSnapshot || !lastBulkUndoSnapshot.items || !lastBulkUndoSnapshot.items.length) {
                showToast("No bulk update is available to undo in this browser session.", "error");
                return;
            }

            var rows = lastBulkUndoSnapshot.items.map(function (entry) {
                return { item: { id: entry.id, name: entry.name }, oldCents: entry.newCents, newCents: entry.oldCents };
            });

            openConfirm(
                "Undo Last Bulk Update?",
                "This will restore " + rows.length + " product price(s) from the last bulk/margin/.99 action back to their previous prices.",
                async function () {
                    await executeDirectPriceUpdates(connection, rows, "Undo Bulk Update");
                    lastBulkUndoSnapshot = null;
                    saveStoredHistory();
                }
            );
        }

        function showFullPriceHistory() {
            var rows = priceChangeHistory.length ? priceChangeHistory.slice(0, 50).map(function (entry) {
                return "<div><strong>" + escapeHtml(entry.name || "Product") + "</strong><span>" + escapeHtml(formatCurrencyFromCents(entry.oldCents) + " → " + formatCurrencyFromCents(entry.newCents) + " - " + formatRelativeTime(entry.timestamp) + " - " + (entry.user || currentUserLabel)) + "</span></div><div><span>" + escapeHtml(entry.source || "Updated") + "</span></div>";
            }) : [
                "<div><strong>No price history yet</strong><span>Manual saves, bulk updates, margin presets, and .99 rounding will appear here.</span></div><div><span>Ready</span></div>"
            ];
            openFeatureModal("Price Change History", "Recent product price changes stored in this browser for the connected merchant.", rows);
            logActivity("Price History", "Price history opened.", "Viewed");
        }

        function importCsvClicked() {
            var input = byId("csvImportInput");
            if (!input) {
                showToast("CSV import control was not found. Refresh the page and try again.", "error");
                return;
            }

            input.value = "";
            input.click();
        }

        async function importCsvFile(file) {
            if (!file) return;

            var connection = requireConnection();
            if (!connection) return;

            var fileName = String(file.name || "").toLowerCase();
            if (fileName && !fileName.endsWith(".csv")) {
                showToast("Please choose a .csv file exported from InventoryRite or Clover.", "error");
                return;
            }

            try {
                var text = await file.text();
                var rows = parseCSV(text);

                if (!rows.length) {
                    showToast("CSV file is empty or does not include Clover ID rows.", "error");
                    return;
                }

                var previewRows = rows.slice(0, 5);
                var previewHtml = buildCsvPreviewHtml(previewRows);

                openConfirm(
                    "Import " + rows.length + " Product" + (rows.length === 1 ? "" : "s") + "?",
                    "<div style='line-height:1.5;'>" +
                        "<strong>Safe CSV import preview</strong><br>" +
                        "This will update matching Clover products only when a Clover ID is present.<br><br>" +
                        previewHtml +
                        "<br><strong>Supported editable columns:</strong> Product Name/Name, Price, and Cost.<br>" +
                        "Rows without changes will be skipped. This will not create new products." +
                    "</div>",
                    async function () {
                        await applyCsvImport(rows);
                    },
                    true
                );

                logActivity("CSV Import Preview", rows.length + " CSV row(s) ready for confirmation.", "Viewed");
                showToast("CSV preview ready. Confirm to import changes.", "info");
            } catch (error) {
                showToast("Failed to read CSV file: " + (error && error.message ? error.message : "Unknown error."), "error");
            }
        }

        function normalizeCsvHeader(header) {
            return String(header || "")
                .replace(/^﻿/, "")
                .trim()
                .toLowerCase()
                .replace(/[^a-z0-9]+/g, "_")
                .replace(/^_+|_+$/g, "");
        }

        function parseCSV(csvText) {
            var lines = String(csvText || "").split(/\\r?\\n/).filter(function (line) {
                return line.trim();
            });

            if (lines.length < 2) return [];

            var headers = parseCSVRow(lines[0]).map(normalizeCsvHeader);
            var rows = [];

            for (var i = 1; i < lines.length; i++) {
                var values = parseCSVRow(lines[i]);
                var row = {};

                headers.forEach(function (header, index) {
                    if (header) row[header] = values[index] || "";
                });

                var itemId = row.clover_id || row.id || row.item_id || row.product_id;
                if (!itemId) continue;

                row.id = String(itemId || "").trim();
                row.name = row.product_name || row.name || row.item_name || row.title || "";
                row.price = row.price || row.price_dollars || row.sale_price || "";
                row.cost = row.cost || row.cost_dollars || row.unit_cost || "";
                rows.push(row);
            }

            return rows;
        }

        function parseCSVRow(rowText) {
            var result = [];
            var current = "";
            var inQuotes = false;
            var text = String(rowText || "");

            for (var i = 0; i < text.length; i++) {
                var char = text[i];
                var next = text[i + 1];

                if (char === '"' && inQuotes && next === '"') {
                    current += '"';
                    i++;
                    continue;
                }

                if (char === '"') {
                    inQuotes = !inQuotes;
                    continue;
                }

                if (char === "," && !inQuotes) {
                    result.push(current.trim());
                    current = "";
                    continue;
                }

                current += char;
            }

            result.push(current.trim());
            return result;
        }

        function buildCsvPreviewHtml(rows) {
            if (!rows.length) return "<div>No preview rows found.</div>";

            var headers = ["id", "name", "price", "cost"];
            var html = "<div style='max-height:260px;overflow:auto;border:1px solid #e5e7eb;border-radius:12px;'>";
            html += "<table style='width:100%;font-size:12px;border-collapse:collapse;background:white;'>";
            html += "<tr>" + headers.map(function (header) {
                return "<th style='border-bottom:1px solid #e5e7eb;padding:7px;text-align:left;background:#f8fafc;'>" + escapeHtml(header.toUpperCase()) + "</th>";
            }).join("") + "</tr>";

            rows.forEach(function (row) {
                html += "<tr>" + headers.map(function (header) {
                    return "<td style='border-bottom:1px solid #f1f5f9;padding:7px;'>" + escapeHtml(row[header] || "") + "</td>";
                }).join("") + "</tr>";
            });

            html += "</table></div>";
            return html;
        }

        async function applyCsvImport(rows) {
            if (isBusy) return;

            var connection = requireConnection();
            if (!connection) return;

            startBusy();

            var successCount = 0;
            var failCount = 0;
            var skippedCount = 0;
            var undoSnapshot = {
                source: "CSV Import",
                timestamp: new Date().toISOString(),
                items: []
            };

            for (var i = 0; i < rows.length; i++) {
                var row = rows[i];
                var itemId = String(row.id || "").trim();
                var existingItem = (loadedItems || []).find(function (item) {
                    return String(item.id || "") === itemId;
                });

                if (!itemId || !existingItem) {
                    skippedCount++;
                    continue;
                }

                var newName = row.name ? String(row.name).trim() : (existingItem.name || "");
                var oldPriceCents = Number(existingItem.price || 0);
                var oldCostCents = getCostCents(itemId);
                var newPriceCents = row.price ? priceToCentsFromDollarsString(row.price) : oldPriceCents;
                var newCostCents = row.cost ? priceToCentsFromDollarsString(row.cost) : oldCostCents;

                if (!newName || newPriceCents === null || newCostCents === null) {
                    skippedCount++;
                    continue;
                }

                var nameChanged = newName !== (existingItem.name || "");
                var priceChanged = newPriceCents !== oldPriceCents;
                var costChanged = newCostCents !== oldCostCents;

                if (!nameChanged && !priceChanged && !costChanged) {
                    skippedCount++;
                    continue;
                }

                try {
                    if (nameChanged || priceChanged) {
                        await fetchJson(
                            "/clover-update-item/" + encodeURIComponent(itemId),
                            {
                                method: "POST",
                                headers: { "Content-Type": "application/json" },
                                body: JSON.stringify({ name: newName, price: newPriceCents })
                            }
                        );
                    }

                    if (costChanged) {
                        await fetchJson(
                            "/item-cost/" + encodeURIComponent(itemId),
                            {
                                method: "POST",
                                headers: { "Content-Type": "application/json" },
                                body: JSON.stringify({ costCents: newCostCents })
                            }
                        );
                        itemCosts[itemId] = newCostCents;
                    }

                    existingItem.name = newName;
                    existingItem.price = newPriceCents;
                    existingItem.cost = newCostCents;

                    if (priceChanged) {
                        recordPriceChange({ id: itemId, name: newName }, oldPriceCents, newPriceCents, "CSV Import");
                        undoSnapshot.items.push({ id: itemId, name: newName, oldCents: oldPriceCents, newCents: newPriceCents });
                        bulkUpdatedItemIds.push(itemId);
                    }

                    successCount++;
                } catch (err) {
                    failCount++;
                    console.error("CSV import failed for item", itemId, err);
                }

                if ((i + 1) % 10 === 0) {
                    showToast("CSV import running: " + successCount + " updated, " + failCount + " failed, " + skippedCount + " skipped.", "info");
                }
            }

            if (undoSnapshot.items.length) {
                lastBulkUndoSnapshot = undoSnapshot;
                saveStoredHistory();
            }

            markSavedNow();
            logActivity("CSV Import", successCount + " updated, " + failCount + " failed, " + skippedCount + " skipped.", failCount ? "Partial" : "Success");
            showToast("CSV Import complete: " + successCount + " updated, " + failCount + " failed, " + skippedCount + " skipped.", failCount ? "error" : "success");

            stopBusy();
            await loadItems();
        }

        /*
        |------------------------------------------------------------------
        | RENDER ITEMS
        |------------------------------------------------------------------
        */

        function renderItems(items) {
            var body = byId("itemsBody");
            if (!body) return;

            body.innerHTML = "";

            var searchBox = byId("inventorySearch");
            var search = searchBox && searchBox.value ? searchBox.value.trim().toLowerCase() : "";

            var baseItems = (items || []).filter(function (item) {
                if (activeViewMode === "lowStock") {
                    var qty = getItemQuantity(item);
                    if (!(qty !== null && qty <= 5)) return false;
                }
                if (activeViewMode === "profitAlerts") {
                    var priceForAlert = Number(item.price || 0);
                    var costForAlert = getCostCents(item.id || "");
                    var marginForAlert = calculateMargin(priceForAlert, costForAlert);
                    if (!(priceForAlert > 0 && costForAlert > 0 && (priceForAlert < costForAlert || (marginForAlert !== null && marginForAlert < 30)))) return false;
                }
                if (activeViewMode === "cleanup") {
                    var cleanupIssues = getCleanupIssues();
                    var cleanupIds = cleanupIssues.map(function (issue) { return issue.item.id || ""; });
                    if (cleanupIds.indexOf(item.id || "") < 0) return false;
                }
                if (activeViewMode === "missingCost") {
                    if (getCostCents(item.id || "") > 0) return false;
                }
                if (activeViewMode === "duplicates") {
                    var duplicateIds = getDuplicateProductIds();
                    if (!duplicateIds[item.id || ""]) return false;
                }
                return true;
            });

            var filtered = baseItems.filter(function (item) {
                if (!search) return true;
                var sku = getItemSku(item);
                var haystack = [item.name || "", sku, item.id || ""].join(" ").toLowerCase();
                return haystack.indexOf(search) >= 0;
            }).sort(function (a, b) {
                return String(a.name || "").localeCompare(String(b.name || ""));
            });

            updateStats(items || []);

            if (!items || !items.length) {
                body.innerHTML =
                    '<tr><td colspan="6" class="empty">' +
                    '<strong>No Clover products found.</strong>' +
                    'Click Add Product to create your first item.' +
                    '</td></tr>';
                syncBulkUI();
                return;
            }

            if (!filtered.length) {
                body.innerHTML =
                    '<tr><td colspan="6" class="empty">' +
                    '<strong>No matching products found.</strong>' +
                    'Try a different product name, SKU, or Clover ID.' +
                    '</td></tr>';
                syncBulkUI();
                return;
            }

            filtered.forEach(function (item) {
                var row = document.createElement("tr");
                var sku = item.sku || item.code || item.productCode || "-";
                var available = item.available === false ? '<span class="pill warn">No</span>' : '<span class="pill good">Yes</span>';
                var hidden = item.hidden ? '<span class="pill warn">Hidden</span>' : '<span class="pill good">Visible</span>';
                var revenue = item.isRevenue === false ? '<span class="pill warn">No</span>' : '<span class="pill good">Yes</span>';
                var itemId = item.id || "";
                var itemName = item.name || "Unnamed Product";
                var priceCents = Number(item.price || 0);
                var priceDollars = (priceCents / 100).toFixed(2);
                var costCents = getCostCents(itemId);
                var costDollars = (costCents / 100).toFixed(2);
                var profitCents = priceCents - costCents;
                var profitClass = profitCents < 0 ? "profit-negative" : "profit-positive";
                var isSelected = selectedItemIds.has(itemId);
                var isBulkUpdated = bulkUpdatedItemIds.indexOf(itemId) >= 0;

                row.setAttribute("data-row-id", itemId);

                if (lastUpdatedItemId && itemId === lastUpdatedItemId) {
                    row.className = "row-updated";
                } else if (isBulkUpdated) {
                    row.className = "row-bulk-updated";
                }

                if (profitCents < 0 && costCents > 0) {
                    row.classList.add("row-below-cost");
                }

                if (costCents <= 0) {
                    row.classList.add("row-missing-cost");
                }

                if (isSelected) {
                    row.classList.add("row-selected");
                }

                row.innerHTML =
                    "<td class='col-check'><input type='checkbox' data-item-id='" + escapeHtml(itemId) + "' " + (isSelected ? "checked" : "") + " /></td>" +
                    "<td class='product-name-cell'><input class='name-input' data-name-for='" + escapeHtml(itemId) + "' value='" + escapeHtml(itemName) + "' /></td>" +
                    "<td><input class='small-input' data-price-for='" + escapeHtml(itemId) + "' value='" + escapeHtml(priceDollars) + "' /></td>" +
                    "<td><input class='small-input' data-cost-for='" + escapeHtml(itemId) + "' value='" + escapeHtml(costDollars) + "' title='Your cost of goods. Saves to InventoryRite and attempts to sync to Clover.' />" + (costCents <= 0 ? "<span class='cost-warning-chip'>Cost needed</span>" : "") + "</td>" +
                    "<td>" + getMarginPill(priceCents, costCents) + "</td>" +
                    "<td><div class='row-actions'>" +
                        "<button type='button' class='btn btn-secondary btn-small icon-action' title='Save product' aria-label='Save product' data-action='save' data-id='" + escapeHtml(itemId) + "'>&#10003;</button>" +
                        "<button type='button' class='btn btn-light btn-small icon-action' title='View details' aria-label='View details' data-action='details' data-id='" + escapeHtml(itemId) + "'>i</button>" +
                        "<button type='button' class='btn btn-danger btn-small icon-action' title='Delete product' aria-label='Delete product' data-action='delete' data-id='" + escapeHtml(itemId) + "' data-name='" + escapeHtml(itemName) + "'>&times;</button>" +
                    "</div></td>";

                body.appendChild(row);
            });

            if (lastUpdatedItemId) {
                setTimeout(function () {
                    lastUpdatedItemId = "";
                    renderItems(loadedItems);
                }, 1400);
            }

            if (bulkUpdatedItemIds.length > 0) {
                setTimeout(function () {
                    bulkUpdatedItemIds = [];
                    renderItems(loadedItems);
                }, 1800);
            }

            // Wire up row checkboxes after render
            var checkboxes = body.querySelectorAll("input[type='checkbox'][data-item-id]");
            checkboxes.forEach(function (cb) {
                cb.addEventListener("change", function (e) {
                    var id = e.target.getAttribute("data-item-id");
                    toggleItemSelection(id, e.target.checked);
                });
            });

            // Wire up cost inputs after render
            var costInputs = body.querySelectorAll("input[data-cost-for]");
            costInputs.forEach(function (input) {
                input.addEventListener("blur", function (e) {
                    var nextTarget = e.relatedTarget || null;
                    if (nextTarget && nextTarget.getAttribute && nextTarget.getAttribute("data-action") === "save") {
                        return;
                    }
                    saveItemCost(e.target.getAttribute("data-cost-for"), e.target.value);
                });
                input.addEventListener("keydown", function (e) {
                    if (e.key === "Enter") {
                        e.preventDefault();
                        updateItem(e.target.getAttribute("data-cost-for"));
                    }
                });
            });

            syncBulkUI();
        }

        async function fetchJson(url, options) {
            options = options || {};

            // Browser-side timeout so the dashboard never stays locked forever
            // if Clover/Render is slow or a request hangs.
            var controller = new AbortController();
            var timeoutId = setTimeout(function () {
                try { controller.abort(); } catch (e) {}
            }, 25000);

            if (!options.signal) {
                options.signal = controller.signal;
            }

            options.headers = options.headers || {};
            options.headers["Accept"] = "application/json";
            if (options.method && String(options.method).toUpperCase() !== "GET") {
                options.headers["X-CSRF-Token"] = embeddedConnection.csrf_token || "";
            }
            if (embeddedConnection.merchant_id) {
                options.headers["X-Merchant-Id"] = embeddedConnection.merchant_id;
            }

            var response;
            try {
                response = await fetch(url, options);
            } catch (fetchError) {
                clearTimeout(timeoutId);
                if (fetchError && fetchError.name === "AbortError") {
                    throw new Error("Request timed out. Please refresh inventory again.");
                }
                throw fetchError;
            } finally {
                clearTimeout(timeoutId);
            }

            var data = null;

            try {
                data = await response.json();
            } catch (jsonError) {
                data = {
                    success: false,
                    message: "Server returned a non-JSON response."
                };
            }

            if (!response.ok) {
                var errorMessage = data && data.message ? data.message : "Request failed.";
                if (data && data.error) {
                    if (typeof data.error === "string") {
                        errorMessage += " " + data.error;
                    } else if (data.error.message) {
                        errorMessage += " " + data.error.message;
                    }
                }
                throw new Error(errorMessage);
            }

            return data;
        }

        function openConfirm(title, message, onConfirm, allowHtml) {
            pendingConfirmAction = onConfirm;

            var modal = byId("confirmModal");
            var titleEl = byId("confirmTitle");
            var messageEl = byId("confirmMessage");

            if (titleEl) titleEl.textContent = title || "Confirm Action";
            if (messageEl) {
                if (allowHtml) messageEl.innerHTML = message || "Are you sure?";
                else messageEl.textContent = message || "Are you sure?";
            }
            if (modal) modal.classList.add("show");
        }

        function closeConfirm() {
            pendingConfirmAction = null;
            var modal = byId("confirmModal");
            if (modal) modal.classList.remove("show");
        }

        function openItemDetails(itemId) {
            var item = loadedItems.find(function (it) { return it.id === itemId; });
            if (!item) return;

            var sku = item.sku || item.code || item.productCode || "-";
            var available = item.available === false ? "No" : "Yes";
            var hidden = item.hidden ? "Hidden" : "Visible";
            var revenue = item.isRevenue === false ? "No" : "Yes";
            var priceCents = Number(item.price || 0);
            var costCents = getCostCents(item.id || "");
            var profitCents = priceCents - costCents;
            var margin = calculateMargin(priceCents, costCents);

            var title = byId("detailsTitle");
            var grid = byId("detailsGrid");
            var modal = byId("detailsModal");

            if (title) title.textContent = item.name || "Product Details";
            if (grid) {
                grid.innerHTML =
                    "<div class='detail-label'>SKU / Code</div><div class='detail-value'>" + escapeHtml(sku) + "</div>" +
                    "<div class='detail-label'>Clover ID</div><div class='detail-value'>" + escapeHtml(item.id || "-") + "</div>" +
                    "<div class='detail-label'>Available</div><div class='detail-value'>" + escapeHtml(available) + "</div>" +
                    "<div class='detail-label'>Hidden</div><div class='detail-value'>" + escapeHtml(hidden) + "</div>" +
                    "<div class='detail-label'>Revenue Item</div><div class='detail-value'>" + escapeHtml(revenue) + "</div>" +
                    "<div class='detail-label'>Modified</div><div class='detail-value'>" + escapeHtml(formatDateFromClover(item.modifiedTime)) + "</div>" +
                    "<div class='detail-label'>Price</div><div class='detail-value'>" + escapeHtml(formatCurrencyFromCents(priceCents)) + "</div>" +
                    "<div class='detail-label'>Cost</div><div class='detail-value'>" + escapeHtml(formatCurrencyFromCents(costCents)) + "</div>" +
                    "<div class='detail-label'>Profit / Unit</div><div class='detail-value'>" + escapeHtml(formatCurrencyFromCents(profitCents)) + "</div>" +
                    "<div class='detail-label'>Margin</div><div class='detail-value'>" + escapeHtml(margin === null ? "-" : margin.toFixed(1) + "%") + "</div>";
            }

            if (modal) modal.classList.add("show");
        }

        function closeItemDetails() {
            var modal = byId("detailsModal");
            if (modal) modal.classList.remove("show");
        }

        async function saveItemCost(itemId, value) {
            try {
                var connection = requireConnection();
                if (!connection || !itemId) return;

                var costCents = priceToCentsFromDollarsString(value);
                if (costCents === null) {
                    showToast("Cost must be a valid dollar amount.", "error");
                    renderItems(loadedItems);
                    return;
                }

                var savedCost = await fetchJson(
                    "/item-cost/" + encodeURIComponent(itemId),
                    {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ costCents: costCents })
                    }
                );

                itemCosts[itemId] = costCents;
                markSavedNow();
                var costItem = (loadedItems || []).find(function (x) { return (x.id || "") === itemId; }) || { name: itemId };
                logActivity("Cost Saved", (costItem.name || "Product") + " cost saved at " + formatCurrencyFromCents(costCents) + ".", "Success");
                showToast(savedCost && savedCost.message ? savedCost.message : "Cost saved. Margin updated.", "success");
                renderItems(loadedItems);
            } catch (error) {
                showToast(error && error.message ? error.message : "Unable to save cost.", "error");
            }
        }

        async function loadItems() {
            if (isBusy) return;

            try {
                var connection = requireConnection();
                if (!connection) return;

                startBusy();
                setButtonText("btnRefreshInventory", "Refreshing...");
                setButtonText("btnRefreshInventoryTop", "Refreshing...");

                var requestHeaders = {};
                if (connection.merchantId) {
                    requestHeaders["X-Merchant-Id"] = connection.merchantId;
                }

                var data = await fetchJson(
                    "/clover-items",
                    { headers: requestHeaders }
                );

                var costData = await fetchJson(
                    "/item-costs",
                    { headers: requestHeaders }
                );

                loadedItems = data.data && data.data.elements ? data.data.elements : [];
                itemCosts = costData.costs || {};

                loadedItems.forEach(function (item) {
                    if (!item || !item.id) return;
                    if ((itemCosts[item.id] === undefined || Number(itemCosts[item.id]) === 0) && item.cost !== undefined && item.cost !== null) {
                        itemCosts[item.id] = Number(item.cost || 0);
                    }
                });

                loadStoredHistory();
                renderItems(loadedItems);
                updateLastSyncNote();
                showToast("Inventory loaded: " + loadedItems.length + " product(s).", "success");
                logActivity("Inventory Loaded", loadedItems.length + " product(s) synced from Clover.", "Success");
            } catch (error) {
                showToast(error && error.message ? error.message : "Unable to load inventory.", "error");
            } finally {
                setButtonText("btnRefreshInventory", "Refresh");
                setButtonText("btnRefreshInventoryTop", "Refresh");
                stopBusy();
            }
        }

        async function createItem() {
            if (isBusy) return;

            try {
                var connection = requireConnection();
                if (!connection) return;

                var nameBox = byId("itemName");
                var priceBox = byId("itemPrice");

                var name = nameBox && nameBox.value ? nameBox.value.trim() : "New Clover Item";
                var price = priceBox && priceBox.value ? priceBox.value.trim() : "199";

                if (!name) {
                    showToast("Product name cannot be empty.", "error");
                    return;
                }

                if (Number.isNaN(Number(price)) || Number(price) < 0) {
                    showToast("Price cents must be a valid positive number.", "error");
                    return;
                }

                startBusy();
                setButtonText("btnRefreshInventory", "Refreshing...");
                setButtonText("btnRefreshInventoryTop", "Refreshing...");

                var data = await fetchJson(
                    "/clover-create-item",
                    {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ name: name, price: Number(price) })
                    }
                );

                lastUpdatedItemId = data && data.data && data.data.id ? data.data.id : "";
                recordPriceChange({ id: lastUpdatedItemId, name: name }, 0, Number(price), "Product Created");
                showToast("Product created successfully.", "success");
                logActivity("Product Created", name + " was created in Clover.", "Success");

                var addPanel = byId("addPanel");
                if (addPanel) addPanel.classList.remove("show");

                stopBusy();
                await loadItems();
            } catch (error) {
                showToast(error && error.message ? error.message : "Unable to create product.", "error");
                stopBusy();
            }
        }

        async function updateItem(itemId) {
            if (isBusy) return;

            try {
                var connection = requireConnection();
                if (!connection) return;

                var nameBox = document.querySelector("[data-name-for='" + itemId + "']");
                var priceBox = document.querySelector("[data-price-for='" + itemId + "']");
                var costBox = document.querySelector("[data-cost-for='" + itemId + "']");

                var name = nameBox && nameBox.value ? nameBox.value.trim() : "";
                var priceCents = priceToCentsFromDollarsString(priceBox && priceBox.value ? priceBox.value : "0");
                var costCents = priceToCentsFromDollarsString(costBox && costBox.value ? costBox.value : "0");
                var existingItem = (loadedItems || []).find(function (x) { return (x.id || "") === itemId; });
                var oldPriceCents = existingItem ? Number(existingItem.price || 0) : 0;
                var oldCostCents = getCostCents(itemId);

                if (!name) {
                    showToast("Product name cannot be empty.", "error");
                    return;
                }

                if (priceCents === null) {
                    showToast("Price must be a valid dollar amount.", "error");
                    return;
                }

                if (costCents === null) {
                    showToast("Cost must be a valid dollar amount.", "error");
                    return;
                }

                startBusy();

                await fetchJson(
                    "/clover-update-item/" + encodeURIComponent(itemId),
                    {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ name: name, price: priceCents })
                    }
                );

                var savedCost = await fetchJson(
                    "/item-cost/" + encodeURIComponent(itemId),
                    {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ costCents: costCents })
                    }
                );

                itemCosts[itemId] = costCents;

                if (existingItem) {
                    existingItem.name = name;
                    existingItem.price = priceCents;
                    existingItem.cost = costCents;
                }

                lastUpdatedItemId = itemId;
                markSavedNow();
                recordPriceChange({ id: itemId, name: name }, oldPriceCents, priceCents, "Manual Row Save");
                logActivity("Product Saved", name + " price and cost were saved to Clover.", "Success");
                showToast(savedCost && savedCost.cloverCostSynced ? "Product price and cost saved to Clover." : "Product updated. Cost saved locally.", "success");

                stopBusy();
                await loadItems();
            } catch (error) {
                showToast(error && error.message ? error.message : "Unable to update product.", "error");
                stopBusy();
            }
        }

        async function deleteItem(itemId) {
            if (isBusy) return;

            try {
                var connection = requireConnection();
                if (!connection) return;

                startBusy();

                await fetchJson(
                    "/clover-delete-item/" + encodeURIComponent(itemId),
                    { method: "POST" }
                );

                showToast("Product deleted.", "success");
                logActivity("Product Deleted", "A product was deleted from Clover.", "Success");

                stopBusy();
                await loadItems();
            } catch (error) {
                showToast(error && error.message ? error.message : "Unable to delete product.", "error");
                stopBusy();
            }
        }

        function toggleAddPanel() {
            var addPanel = byId("addPanel");
            if (!addPanel) return;
            addPanel.classList.toggle("show");

            if (addPanel.classList.contains("show")) {
                var itemName = byId("itemName");
                if (itemName) itemName.focus();
            }
        }

        function toggleBulkPanel() {
            var bulkPanel = byId("bulkPanel");
            if (!bulkPanel) return;
            bulkPanel.classList.toggle("show");

            if (bulkPanel.classList.contains("show")) {
                var pctInput = byId("bulkPct");
                if (pctInput) pctInput.focus();
            }
        }

        function toggleAdvancedTools() {
            document.body.classList.toggle("show-advanced");

            var isOpen = document.body.classList.contains("show-advanced");
            var label = isOpen ? "Hide Advanced" : "Advanced Tools";

            var topButton = byId("btnToggleAdvancedTop");
            if (topButton) topButton.textContent = label;

            var heroButton = byId("btnHeroAdvanced");
            if (heroButton) heroButton.textContent = label;

            showToast(isOpen ? "Advanced tools are now visible." : "Advanced tools are hidden for a cleaner view.", "info");
        }

        /*
        |------------------------------------------------------------------
        | EVENT BINDINGS
        |------------------------------------------------------------------
        */


        bind("btnShowAllProducts", "click", function () { setViewMode("all"); logActivity("All Products", "All products view restored.", "Viewed"); showToast("Showing all products.", "info"); });
        bind("btnLowStock", "click", showLowStock);
        bind("btnReorder", "click", showReorderPlanning);
        bind("btnExportCsv", "click", exportProductsCsv);
        bind("btnImportCsv", "click", importCsvClicked);

        var csvInput = byId("csvImportInput");
        if (csvInput) {
            csvInput.addEventListener("change", function (event) {
                var file = event.target && event.target.files && event.target.files[0] ? event.target.files[0] : null;
                if (file) importCsvFile(file);
            });
        }
        bind("btnDuplicateReview", "click", showDuplicateDetector);
        bind("btnMissingCostLock", "click", showMissingCostLock);
        bind("btnSmart99", "click", applySmart99Rounding);
        bind("btnUndoBulk", "click", undoLastBulkUpdate);
        bind("btnOpenPriceHistory", "click", showFullPriceHistory);
        bind("btnPriceRules", "click", showSmartPricing);
        bind("btnProfitAlerts", "click", showProfitAlerts);
        bind("btnCleanupScan", "click", showCleanupTools);
        bind("btnActivityLog", "click", showActivityLog);
        bind("btnProfitIntelligence", "click", showProfitIntelligence);
        bind("btnBulkOperationsHub", "click", showBulkOperationsHub);
        bind("btnSmartPricingHub", "click", showSmartPricing);
        bind("btnCleanupToolsHub", "click", showCleanupTools);
        bind("btnShortcutHub", "click", showOperationalShortcuts);
        bind("featureClose", "click", closeFeatureModal);

        bind("btnRefreshInventoryTop", "click", loadItems);
        bind("btnRefreshInventory", "click", loadItems);
        bind("btnHeroSync", "click", loadItems);
        bind("btnHeroAdd", "click", toggleAddPanel);
        bind("btnHeroAdvanced", "click", toggleAdvancedTools);
        bind("btnToggleAdvancedTop", "click", toggleAdvancedTools);
        bind("btnToggleAddTop", "click", toggleAddPanel);
        bind("btnToggleAdd", "click", toggleAddPanel);
        bind("btnToggleBulkTop", "click", toggleBulkPanel);
        bind("btnToggleBulk", "click", toggleBulkPanel);
        bind("btnCreateItem", "click", createItem);
        bind("inventorySearch", "input", function () { renderItems(loadedItems); });

        bind("confirmCancel", "click", closeConfirm);
        bind("confirmYes", "click", function () {
            var action = pendingConfirmAction;
            closeConfirm();
            if (typeof action === "function") action();
        });
        bind("detailsClose", "click", closeItemDetails);
        updateLastSavedStatus();
        setInterval(updateLastSavedStatus, 5000);

        // Select-all checkbox
        bind("selectAllCheckbox", "change", function (e) {
            selectAllVisible(e.target.checked);
        });

        // Bulk action buttons
        bind("btnBulkIncrease", "click", function () { runBulkPriceUpdate("increase"); });
        bind("btnBulkDecrease", "click", function () { runBulkPriceUpdate("decrease"); });
        bind("btnBulkClearPanel", "click", function () {
            clearSelection();
            renderItems(loadedItems);
        });

        document.querySelectorAll("[data-margin-preset]").forEach(function (btn) {
            btn.addEventListener("click", function () {
                applyQuickMarginPreset(Number(btn.getAttribute("data-margin-preset")));
            });
        });

        var modal = byId("confirmModal");
        if (modal) {
            modal.addEventListener("click", function (event) {
                if (event.target === modal) closeConfirm();
            });
        }

        var detailsModal = byId("detailsModal");
        if (detailsModal) {
            detailsModal.addEventListener("click", function (event) {
                if (event.target === detailsModal) closeItemDetails();
            });
        }


        var featureModal = byId("featureModal");
        if (featureModal) {
            featureModal.addEventListener("click", function (event) {
                if (event.target === featureModal) {
                    closeFeatureModal();
                    return;
                }
                var target = event.target;
                if (target && target.getAttribute && target.getAttribute("data-fix-action")) {
                    handleInsightFixAction(target.getAttribute("data-fix-action"), target.getAttribute("data-fix-id"));
                }
            });
        }

        var itemsBody = byId("itemsBody");
        if (itemsBody) {
            itemsBody.addEventListener("click", function (event) {
                var target = event.target;
                if (!target || !target.getAttribute) return;

                var action = target.getAttribute("data-action");
                var itemId = target.getAttribute("data-id");
                var itemName = target.getAttribute("data-name") || "this product";

                if (action === "save") {
                    updateItem(itemId);
                }

                if (action === "details") {
                    openItemDetails(itemId);
                }

                if (action === "delete") {
                    openConfirm(
                        "Delete Product?",
                        "This will delete " + itemName + " from Clover. This cannot be undone.",
                        function () { deleteItem(itemId); }
                    );
                }
            });
        }

        loadStoredHistory();

        if (embeddedConnection.connected) {
            loadItems();
        }
    })();
    

// btnFixMargins handler removed: no matching button exists in this UI.



</script>

</body>
</html>`;
}

/*
|--------------------------------------------------------------------------
| ROOT + CLOVER OAUTH CALLBACK HANDLER
|--------------------------------------------------------------------------
*/

app.get("/", (req, res) => {
    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");
    return res.send(renderDashboard());
});

async function handleOAuthCallback(req, res) {
    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");

    try {
        const code = req.query.code;

        if (!code) {
            return res.redirect("/");
        }

        if (!CLOVER_CLIENT_ID || !CLOVER_CLIENT_SECRET) {
            return res.status(500).send(`
                <h1>Missing Clover environment variables</h1>
                <p>Please add CLOVER_CLIENT_ID and CLOVER_CLIENT_SECRET inside Render.</p>
                <a href="/">Back to InventoryRite</a>
            `);
        }

        const state = String(req.query.state || "");
        const cookies = parseCookies(req);
        const cookieState = cookies.inventoryrite_oauth_state || "";
        const storedState = oauthStates.get(state);

        if (!state || !cookieState || state !== cookieState || !storedState || storedState.expiresAt <= nowMs()) {
            return res.status(400).send(`
                <h1>Clover OAuth security check failed</h1>
                <p>Please restart the Clover connection from InventoryRite.</p>
                <a href="/">Back to InventoryRite</a>
            `);
        }

        oauthStates.delete(state);
        res.setHeader("Set-Cookie", `inventoryrite_oauth_state=; HttpOnly; SameSite=Lax; Max-Age=0; Path=/`);

        console.log("Clover OAuth code received.");

        const tokenResponse = await cloverApi.post(
            `${CLOVER_API_BASE_URL}/oauth/token`,
            new URLSearchParams({
                client_id: CLOVER_CLIENT_ID,
                client_secret: CLOVER_CLIENT_SECRET,
                code: code,
                redirect_uri: REDIRECT_URI
            }).toString(),
            { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
        );

        const tokenData = tokenResponse.data || {};

        let detectedMerchantId =
            req.query.merchant_id ||
            req.query.merchantId ||
            req.query.mId ||
            tokenData.merchant_id ||
            tokenData.merchantId ||
            tokenData.mid ||
            tokenData.merchant?.id ||
            "";

        const detectedEmployeeId =
            req.query.employee_id ||
            req.query.employeeId ||
            tokenData.employee_id ||
            tokenData.employeeId ||
            tokenData.employee?.id ||
            "";

        if (!detectedMerchantId && tokenData.access_token) {
            try {
                const merchantsResponse = await cloverApi.get(
                    `${CLOVER_API_BASE_URL}/v3/merchants?limit=1`,
                    { headers: cloverHeaders(tokenData.access_token) }
                );
                detectedMerchantId = merchantsResponse.data?.elements?.[0]?.id || "";
            } catch (merchantLookupError) {
                console.warn("Unable to auto-detect Clover merchant id:", merchantLookupError.response?.data || merchantLookupError.message);
            }
        }

        await saveCloverConnection({
            merchant_id: detectedMerchantId,
            employee_id: detectedEmployeeId,
            access_token: tokenData.access_token || "",
            refresh_token: tokenData.refresh_token || "",
            token_expires_at: tokenData.expires_in ? new Date(nowMs() + Number(tokenData.expires_in) * 1000).toISOString() : "",
            scopes: tokenData.scope || tokenData.scopes || "",
            connected_at: new Date().toISOString()
        });

        logApiCall("/oauth-callback", latestCloverConnection.merchant_id, "GET", 200);
        console.log("Clover connected successfully.", {
            merchant_id: latestCloverConnection.merchant_id,
            employee_id: latestCloverConnection.employee_id,
            hasAccessToken: !!latestCloverConnection.access_token,
            hasRefreshToken: !!latestCloverConnection.refresh_token,
            token_expires_at: latestCloverConnection.token_expires_at
        });

        return res.send(renderDashboard(latestCloverConnection));
    } catch (error) {
        console.error("Clover OAuth Callback Error:", error.response?.data || error.message);
        logApiCall("/oauth-callback", "", "GET", error.response?.status || 500);

        return res.status(500).send(`
            <h1>Clover OAuth failed</h1>
            <pre>${safe(JSON.stringify(error.response?.data || error.message, null, 2))}</pre>
            <a href="/">Back to InventoryRite</a>
        `);
    }
}

app.get("/oauth-callback", handleOAuthCallback);

// Backward-compatible callback support in case the Clover dashboard still has the old root redirect during testing.
app.get("/callback", handleOAuthCallback);

app.get("/icon.png", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "icon.png"));
});

app.get("/.well-known/clover.json", (req, res) => {
    res.json({
        app_id: CLOVER_APP_ID || null,
        app_name: CLOVER_APP_NAME,
        webhook_url: `${APP_BASE_URL}/clover-webhook`,
        uninstall_url: `${APP_BASE_URL}/clover-uninstall`,
        version: APP_VERSION,
        events: [
            "ITEM_CREATED",
            "ITEM_UPDATED",
            "ITEM_DELETED",
            "INVENTORY_CHANGED"
        ]
    });
});

/*
|--------------------------------------------------------------------------
| HEALTH ROUTE
|--------------------------------------------------------------------------
*/

app.get("/health", (req, res) => {
    res.json({
        success: true,
        message: "InventoryRite backend healthy",
        appBaseUrl: APP_BASE_URL,
        redirectUri: REDIRECT_URI,
        cloverEnvironment: IS_PRODUCTION_CLOVER ? "production" : "sandbox",
        cloverClientIdLoaded: !!CLOVER_CLIENT_ID,
        cloverSecretLoaded: !!CLOVER_CLIENT_SECRET,
        cloverAppIdLoaded: !!CLOVER_APP_ID,
        encryptionReady: hasValidEncryptionKey(),
        webhookSecretLoaded: !!CLOVER_WEBHOOK_SECRET,
        databaseEnabled: USE_DATABASE,
        latestConnection: {
            connected: latestCloverConnection.connected,
            merchant_id: latestCloverConnection.merchant_id,
            employee_id: latestCloverConnection.employee_id,
            connected_at: latestCloverConnection.connected_at,
            hasAccessToken: !!latestCloverConnection.access_token,
            hasRefreshToken: !!latestCloverConnection.refresh_token,
            token_expires_at: latestCloverConnection.token_expires_at
        }
    });
});

/*
|--------------------------------------------------------------------------
| CLOVER CONNECT ROUTE
|--------------------------------------------------------------------------
*/

app.get("/connect-clover", (req, res) => {
    if (!CLOVER_CLIENT_ID) {
        return res.status(500).json({
            success: false,
            message: "Missing CLOVER_CLIENT_ID in environment variables."
        });
    }

    const state = createToken(24);
    oauthStates.set(state, { expiresAt: nowMs() + OAUTH_STATE_TTL_MS });
    res.setHeader(
        "Set-Cookie",
        `inventoryrite_oauth_state=${encodeURIComponent(state)}; HttpOnly; SameSite=Lax; Max-Age=600; Path=/${SECURE_COOKIE_FLAG}`
    );

    const scope = process.env.CLOVER_SCOPES || REQUIRED_CLOVER_SCOPES.join(" ");

    const cloverAuthUrl =
        `${CLOVER_BASE_URL}/oauth/authorize` +
        `?client_id=${encodeURIComponent(CLOVER_CLIENT_ID)}` +
        `&response_type=code` +
        `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}` +
        `&state=${encodeURIComponent(state)}` +
        `&scope=${encodeURIComponent(scope)}`;

    console.log("Redirecting to Clover OAuth...");
    return res.redirect(cloverAuthUrl);
});

/*
|--------------------------------------------------------------------------
| CLOVER CONNECTION STATUS ROUTE
|--------------------------------------------------------------------------
*/

app.get("/clover-connection", async (req, res) => {
    const { connection } = await getConnectionFromRequest(req);
    res.json({
        success: true,
        connection: {
            connected: !!connection.access_token,
            merchant_id: connection.merchant_id,
            employee_id: connection.employee_id,
            connected_at: connection.connected_at,
            hasAccessToken: !!connection.access_token,
            hasRefreshToken: !!connection.refresh_token,
            token_expires_at: connection.token_expires_at
        }
    });
});

app.get("/sync-debug", async (req, res) => {
    try {
        const { accessToken, merchantId } = await getConnectionFromRequest(req);
        res.json({
            success: true,
            message: accessToken && merchantId ? "Server has a Clover connection." : "Server is missing Clover connection data.",
            databaseEnabled: USE_DATABASE,
            merchantIdPresent: !!merchantId,
            accessTokenPresent: !!accessToken,
            latestConnection: {
                connected: latestCloverConnection.connected,
                merchant_id: latestCloverConnection.merchant_id,
                employee_id: latestCloverConnection.employee_id,
                connected_at: latestCloverConnection.connected_at,
                hasAccessToken: !!latestCloverConnection.access_token,
                hasRefreshToken: !!latestCloverConnection.refresh_token,
                token_expires_at: latestCloverConnection.token_expires_at
            }
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: "Sync debug failed.",
            error: error.message
        });
    }
});

/*
|--------------------------------------------------------------------------
| CLOVER MERCHANT INFO ROUTE
|--------------------------------------------------------------------------
*/

app.get("/clover-merchant", async (req, res) => {
    try {
        const { accessToken, merchantId } = await getConnectionFromRequest(req);

        if (!accessToken || !merchantId) {
            return res.status(400).json({
                success: false,
                message: "Clover is not connected on the server. Click Connect Clover again, then refresh inventory. If this happens after every deploy, add DATABASE_URL so the connection persists."
            });
        }

        const merchantResponse = await cloverApi.get(
            `${CLOVER_API_BASE_URL}/v3/merchants/${merchantId}`,
            { headers: cloverHeaders(accessToken) }
        );

        res.json({
            success: true,
            message: "Clover merchant info loaded successfully",
            data: merchantResponse.data
        });
    } catch (error) {
        console.error("Clover Merchant Error:", error.response?.data || error.message);

        const cloverError = getCloverError(error);
        res.status(cloverError.status).json({
            success: false,
            message: "Failed to load Clover merchant info",
            error: cloverError.data
        });
    }
});

/*
|--------------------------------------------------------------------------
| CLOVER ITEMS ROUTE
|--------------------------------------------------------------------------
*/

app.get("/clover-items", async (req, res) => {
    try {
        const { accessToken, merchantId } = await getConnectionFromRequest(req);

        if (!accessToken || !merchantId) {
            return res.status(400).json({
                success: false,
                message: "Clover inventory cannot sync because the server does not have a saved Clover connection. Click Connect Clover again. For production, set DATABASE_URL so tokens survive Render restarts/deploys."
            });
        }

        const itemsResponse = await cloverApi.get(
            `${CLOVER_API_BASE_URL}/v3/merchants/${merchantId}/items?limit=${CLOVER_ITEM_LIMIT}`,
            { headers: cloverHeaders(accessToken) }
        );

        res.json({
            success: true,
            message: "Clover inventory items loaded successfully",
            data: itemsResponse.data
        });
    } catch (error) {
        console.error("Clover Items Error:", error.response?.data || error.message);

        const cloverError = getCloverError(error);
        res.status(cloverError.status).json({
            success: false,
            message: "Failed to load Clover inventory items",
            error: cloverError.data
        });
    }
});

/*
|--------------------------------------------------------------------------
| CLOVER CREATE ITEM ROUTE - POST
|--------------------------------------------------------------------------
*/

app.post("/clover-create-item", async (req, res) => {
    try {
        const { accessToken, merchantId } = await getConnectionFromRequest(req);

        if (!accessToken || !merchantId) {
            return res.status(400).json({
                success: false,
                message: "Missing token or merchantId."
            });
        }

        const itemName = String(req.body.name || "New Clover Item").trim();
        const itemPrice = Number(req.body.price || 199);

        if (!itemName || !isValidMoneyCents(itemPrice)) {
            return res.status(400).json({
                success: false,
                message: "Invalid item name or price."
            });
        }

        const createResponse = await cloverApi.post(
            `${CLOVER_API_BASE_URL}/v3/merchants/${merchantId}/items`,
            {
                name: itemName,
                price: itemPrice,
                priceType: "FIXED",
                available: true,
                hidden: false,
                isRevenue: true
            },
            { headers: cloverHeaders(accessToken) }
        );

        res.json({
            success: true,
            message: "Clover item created successfully",
            data: createResponse.data
        });
    } catch (error) {
        console.error("Clover Create Item Error:", error.response?.data || error.message);

        const cloverError = getCloverError(error);
        res.status(cloverError.status).json({
            success: false,
            message: "Failed to create Clover item",
            error: cloverError.data
        });
    }
});

/*
|--------------------------------------------------------------------------
| CLOVER UPDATE ITEM ROUTE - POST
|--------------------------------------------------------------------------
*/

app.post("/clover-update-item/:itemId", async (req, res) => {
    try {
        const { accessToken, merchantId } = await getConnectionFromRequest(req);
        const itemId = req.params.itemId;

        if (!accessToken || !merchantId) {
            return res.status(400).json({
                success: false,
                message: "Missing token or merchantId."
            });
        }

        if (!itemId) {
            return res.status(400).json({
                success: false,
                message: "Missing itemId."
            });
        }

        const itemName = String(req.body.name || "").trim();
        const itemPrice = Number(req.body.price);

        if (!itemName || !isValidMoneyCents(itemPrice)) {
            return res.status(400).json({
                success: false,
                message: "Invalid item name or price."
            });
        }

        const updateResponse = await cloverApi.post(
            `${CLOVER_API_BASE_URL}/v3/merchants/${merchantId}/items/${itemId}`,
            {
                name: itemName,
                price: itemPrice,
                priceType: "FIXED",
                available: true,
                hidden: false,
                isRevenue: true
            },
            { headers: cloverHeaders(accessToken) }
        );

        res.json({
            success: true,
            message: "Clover item updated successfully",
            data: updateResponse.data
        });
    } catch (error) {
        console.error("Clover Update Item Error:", error.response?.data || error.message);

        const cloverError = getCloverError(error);
        res.status(cloverError.status).json({
            success: false,
            message: "Failed to update Clover item",
            error: cloverError.data
        });
    }
});

/*
|--------------------------------------------------------------------------
| CLOVER DELETE ITEM ROUTE - POST
|--------------------------------------------------------------------------
*/

app.post("/clover-delete-item/:itemId", async (req, res) => {
    try {
        const { accessToken, merchantId } = await getConnectionFromRequest(req);
        const itemId = req.params.itemId;

        if (!accessToken || !merchantId) {
            return res.status(400).json({
                success: false,
                message: "Missing token or merchantId."
            });
        }

        if (!itemId) {
            return res.status(400).json({
                success: false,
                message: "Missing itemId."
            });
        }

        const deleteResponse = await cloverApi.delete(
            `${CLOVER_API_BASE_URL}/v3/merchants/${merchantId}/items/${itemId}`,
            { headers: cloverHeaders(accessToken) }
        );

        res.json({
            success: true,
            message: "Clover item deleted successfully",
            data: deleteResponse.data || {}
        });
    } catch (error) {
        console.error("Clover Delete Item Error:", error.response?.data || error.message);

        const cloverError = getCloverError(error);
        res.status(cloverError.status).json({
            success: false,
            message: "Failed to delete Clover item",
            error: cloverError.data
        });
    }
});

/*
|--------------------------------------------------------------------------
| LEGACY CREATE ITEM ROUTE - GET
| Kept for backwards compatibility with older button/link tests.
|--------------------------------------------------------------------------
*/

app.get("/clover-create-item-legacy", async (req, res) => {
    try {
        const { accessToken, merchantId } = await getConnectionFromRequest(req);

        if (!accessToken || !merchantId) {
            return res.status(400).json({
                success: false,
                message: "Missing token or merchantId."
            });
        }

        const itemName = String(req.query.name || "New Clover Item").trim();
        const itemPrice = Number(req.query.price || 199);

        if (!itemName || !isValidMoneyCents(itemPrice)) {
            return res.status(400).json({
                success: false,
                message: "Invalid item name or price."
            });
        }

        const createResponse = await cloverApi.post(
            `${CLOVER_API_BASE_URL}/v3/merchants/${merchantId}/items`,
            {
                name: itemName,
                price: itemPrice,
                priceType: "FIXED",
                available: true,
                hidden: false,
                isRevenue: true
            },
            { headers: cloverHeaders(accessToken) }
        );

        res.json({
            success: true,
            message: "Clover item created successfully",
            data: createResponse.data
        });
    } catch (error) {
        console.error("Clover Create Item Error:", error.response?.data || error.message);

        const cloverError = getCloverError(error);
        res.status(cloverError.status).json({
            success: false,
            message: "Failed to create Clover item",
            error: cloverError.data
        });
    }
});


/*
|--------------------------------------------------------------------------
| ITEM COSTS ROUTES - APP DATABASE, NOT CLOVER
|--------------------------------------------------------------------------
| Clover does not store your cost-of-goods field. This app stores merchant
| costs in your own database so margin and profit can be calculated safely.
|--------------------------------------------------------------------------
*/

app.get("/item-costs", async (req, res) => {
    try {
        const { merchantId } = await getConnectionFromRequest(req);

        if (!merchantId) {
            return res.status(400).json({
                success: false,
                message: "Missing merchantId."
            });
        }

        const costs = await getItemCostsForMerchant(merchantId);

        res.json({
            success: true,
            databaseEnabled: USE_DATABASE,
            costs
        });
    } catch (error) {
        console.error("Item Costs Error:", error.message);
        res.status(500).json({
            success: false,
            message: "Failed to load item costs.",
            error: error.message
        });
    }
});
/*
|--------------------------------------------------------------------------
| DEBUG: CLOVER COST FIELD TEST
|--------------------------------------------------------------------------
| Temporary diagnostic route for testing whether Clover accepts cost-like
| fields on item update requests. Keep this ABOVE the catch-all Route not
| found handler. GET confirms the route is deployed. POST performs the test.
|--------------------------------------------------------------------------
*/

app.get("/debug-test-clover-cost", (req, res) => {
    res.json({
        success: true,
        message: "Debug route is installed. Use POST with itemId, fieldName, and costCents to test Clover cost syncing.",
        exampleBody: {
            itemId: "PUT_CLOVER_ITEM_ID_HERE",
            fieldName: "cost",
            costCents: 500
        },
        fieldNamesToTry: ["cost", "costCents", "unitCost", "unitCostCents", "defaultCost"]
    });
});

app.post("/debug-test-clover-cost", async (req, res) => {
    try {
        const { accessToken, merchantId } = await getConnectionFromRequest(req);
        const { itemId, fieldName, costCents } = req.body;

        const allowedFields = new Set(["cost", "costCents", "unitCost", "unitCostCents", "defaultCost"]);

        if (!accessToken || !merchantId) {
            return res.status(401).json({
                success: false,
                message: "Clover is not connected. Open InventoryRite and connect Clover first."
            });
        }

        if (!itemId || !fieldName || costCents === undefined) {
            return res.status(400).json({
                success: false,
                message: "Missing itemId, fieldName, or costCents.",
                exampleBody: {
                    itemId: "PUT_CLOVER_ITEM_ID_HERE",
                    fieldName: "cost",
                    costCents: 500
                }
            });
        }

        if (!allowedFields.has(String(fieldName))) {
            return res.status(400).json({
                success: false,
                message: "Invalid fieldName for this diagnostic route.",
                allowedFields: Array.from(allowedFields)
            });
        }

        if (!isValidMoneyCents(costCents)) {
            return res.status(400).json({
                success: false,
                message: "costCents must be a valid non-negative number. Example: 500 for $5.00."
            });
        }

        const payload = { [fieldName]: Number(costCents) };

        const response = await cloverApi.post(
            `${CLOVER_API_BASE_URL}/v3/merchants/${merchantId}/items/${itemId}`,
            payload,
            { headers: cloverHeaders(accessToken) }
        );

        return res.json({
            success: true,
            message: "Clover test request completed. Now refresh Clover Dashboard and check the item Cost column.",
            merchantId,
            itemId,
            fieldName,
            sentPayload: payload,
            cloverResponse: response.data
        });

    } catch (error) {
        const cloverError = getCloverError(error);

        return res.status(cloverError.status).json({
            success: false,
            message: "Clover cost test failed.",
            error: cloverError.data
        });
    }
});

app.post("/item-cost/:itemId", async (req, res) => {
    try {
        const { accessToken, merchantId } = await getConnectionFromRequest(req);
        const itemId = req.params.itemId;
        const costCents = Number(req.body.costCents || 0);

        if (!accessToken || !merchantId || !itemId) {
            return res.status(400).json({
                success: false,
                message: "Missing Clover connection, merchantId, or itemId."
            });
        }

        if (!isValidMoneyCents(costCents)) {
            return res.status(400).json({
                success: false,
                message: "Invalid cost amount."
            });
        }

        // Save locally first so InventoryRite keeps its own profit/margin record.
        const savedCostCents = await saveItemCostForMerchant(merchantId, itemId, costCents);

        // IMPORTANT: Clover DOES accept the item cost field as cents using { cost: costCents }.
        // This keeps InventoryRite and Clover Dashboard's Cost column in sync.
        const cloverResponse = await cloverApi.post(
            `${CLOVER_API_BASE_URL}/v3/merchants/${merchantId}/items/${itemId}`,
            {
                cost: savedCostCents
            },
            {
                headers: cloverHeaders(accessToken)
            }
        );

        logApiCall("/item-cost/:itemId", merchantId, "POST", 200);

        return res.json({
            success: true,
            message: "Item cost saved successfully in InventoryRite and synced to Clover.",
            databaseEnabled: USE_DATABASE,
            merchantId,
            itemId,
            costCents: savedCostCents,
            cloverCostSynced: true,
            cloverCostSyncError: null,
            cloverResponse: cloverResponse.data
        });
    } catch (error) {
        const cloverError = getCloverError(error);

        console.error("Save Item Cost Error:", error.response?.data || error.message);

        return res.status(cloverError.status).json({
            success: false,
            message: "Failed to save and sync item cost.",
            error: cloverError.data
        });
    }
});

/*
|--------------------------------------------------------------------------
| PUBLIC TRUST PAGES
|--------------------------------------------------------------------------
*/

function renderSimplePage(title, bodyHtml) {
    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>${safe(title)} - InventoryRite for Clover</title>
    <style>
        body { font-family: Arial, Helvetica, sans-serif; background:#f5f7fb; margin:0; padding:28px; color:#111827; line-height:1.6; }
        .wrap { max-width: 880px; margin:0 auto; }
        .card { background:white; border:1px solid #e5e7eb; border-radius:18px; padding:24px; box-shadow:0 12px 35px rgba(15,23,42,.08); }
        h1 { margin:0 0 10px; letter-spacing:-.03em; }
        h2 { margin-top:24px; }
        p, li { color:#475569; }
        a { color:#15803d; font-weight:900; text-decoration:none; }


        /* ----------------------------------------------------------------
        | SIMPLIFIED MERCHANT UI - SIMPLE BY DEFAULT, ADVANCED ON DEMAND
        | Keeps all functionality but hides noisy panels until requested.
        ---------------------------------------------------------------- */

        .simple-hero {
            min-height: auto !important;
            padding: 24px 26px !important;
            align-items: center;
        }

        .simple-hero:after { display: none; }

        .simple-hero-copy { max-width: 720px; }

        .simple-hero h2 {
            font-size: 31px !important;
            line-height: 1.08;
            margin: 0;
        }

        .simple-hero p {
            font-size: 14px !important;
            max-width: 680px;
            margin-top: 9px;
        }

        .simple-hero-actions {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            justify-content: flex-end;
            position: relative;
            z-index: 2;
        }

        .simple-status-strip {
            border-color: #e5e7eb !important;
            background: #ffffff !important;
        }

        .inventory-command-center {
            box-shadow: none !important;
            border-color: #e5e7eb !important;
            background: #ffffff !important;
        }

        .command-search-actions .btn { min-width: 112px; }

        #merchantControlBar,
        #productivityHub,
        #operationsSummaryStrip,
        #lastActionStrip,
        #recentChangesPanel,
        #marginStatsRow,
        .merchant-hint {
            display: none !important;
        }

        body.show-advanced #merchantControlBar { display: flex !important; }
        body.show-advanced #productivityHub { display: grid !important; }
        body.show-advanced #operationsSummaryStrip { display: flex !important; }
        body.show-advanced #lastActionStrip { display: flex !important; }
        body.show-advanced #recentChangesPanel { display: block !important; }
        body.show-advanced #marginStatsRow { display: grid !important; }
        body.show-advanced .merchant-hint { display: block !important; }

        body.show-advanced #btnToggleAdvancedTop,
        body.show-advanced #btnHeroAdvanced {
            background: #111827;
            color: #ffffff;
            border-color: #111827;
        }

        .stats-row:first-of-type {
            margin-top: 4px;
        }

        .stat-box {
            box-shadow: none !important;
        }

        @media (max-width: 760px) {
            .simple-hero {
                flex-direction: column;
                align-items: flex-start;
            }

            .simple-hero-actions {
                width: 100%;
                justify-content: flex-start;
            }

            .simple-hero-actions .btn {
                flex: 1 1 140px;
            }
        }

    </style>
</head>
<body>
    <div class="wrap">
        <p><a href="/">&larr; Back to InventoryRite</a></p>
        <div class="card">
            <h1>${safe(title)}</h1>
            ${bodyHtml}
        </div>
    </div>
</body>
</html>`;
}


function verifyWebhookSignature(req) {
    if (!CLOVER_WEBHOOK_SECRET) {
        // Sandbox/dev mode: allow webhooks when no secret has been configured yet.
        // Production App Market review should set CLOVER_WEBHOOK_SECRET in Render.
        return true;
    }

    const providedSignature =
        req.headers["x-clover-signature"] ||
        req.headers["clover-signature"] ||
        req.headers["x-webhook-signature"] ||
        "";

    if (!providedSignature || !req.rawBody) return false;

    const expectedSignature = crypto
        .createHmac("sha256", CLOVER_WEBHOOK_SECRET)
        .update(req.rawBody)
        .digest("hex");

    const normalizedProvided = String(providedSignature).replace(/^sha256=/i, "").trim();

    try {
        return crypto.timingSafeEqual(
            Buffer.from(normalizedProvided, "hex"),
            Buffer.from(expectedSignature, "hex")
        );
    } catch (error) {
        return false;
    }
}

app.post("/clover-webhook", (req, res) => {
    if (!verifyWebhookSignature(req)) {
        console.warn("Rejected Clover webhook with invalid signature", { requestId: req.id });
        return res.status(401).json({ success: false, message: "Invalid webhook signature." });
    }

    res.status(200).json({ success: true, message: "Webhook received." });

    setImmediate(async () => {
        try {
            const eventType = req.body?.event || req.body?.type || req.body?.eventType || "UNKNOWN";
            const merchantId = req.body?.merchantId || req.body?.merchant_id || req.body?.merchant?.id || "";

            logApiCall("/clover-webhook", merchantId, "POST", 200);
            console.log("Clover webhook processed", { requestId: req.id, eventType, merchantId, body: req.body });

            // InventoryRite currently refreshes live data from Clover when the merchant opens the dashboard.
            // This hook is intentionally safe: it acknowledges Clover immediately and logs the event for review.
            // Add cache invalidation or background sync here later if you add a queue/worker.
        } catch (error) {
            console.error("Clover webhook async processing error:", error.message);
        }
    });
});

app.post("/clover-uninstall", async (req, res) => {
    const merchantId = String(req.body?.merchantId || req.body?.merchant_id || req.body?.merchant?.id || "").trim();

    try {
        if (merchantId && USE_DATABASE && dbPool) {
            await dbPool.query("DELETE FROM item_costs WHERE merchant_id = $1", [merchantId]);
            await dbPool.query("DELETE FROM merchant_connections WHERE merchant_id = $1", [merchantId]);
        }

        if (merchantId && latestCloverConnection.merchant_id === merchantId) {
            latestCloverConnection = {
                connected: false,
                merchant_id: "",
                employee_id: "",
                access_token: "",
                refresh_token: "",
                token_expires_at: "",
                scopes: "",
                connected_at: ""
            };
        }

        logApiCall("/clover-uninstall", merchantId, "POST", 200);
        return res.json({ success: true, message: "Merchant data cleanup complete." });
    } catch (error) {
        console.error("Clover uninstall cleanup error:", error.message);
        logApiCall("/clover-uninstall", merchantId, "POST", 500);
        return res.status(500).json({ success: false, message: "Uninstall cleanup failed.", error: error.message });
    }
});

app.get("/support", (req, res) => {
    res.send(renderSimplePage("Support", `
        <p>Need help with InventoryRite for Clover? Contact Process Rite Inc for setup, product syncing, pricing tools, and account support.</p>
        <h2>Support Contact</h2>
        <p>Email: <a href="mailto:muheisenone@outlook.com">muheisenone@outlook.com</a></p>
        <p>Phone: 862-247-6067</p>
        <h2>What We Help With</h2>
        <ul>
            <li>Clover connection and authorization issues</li>
            <li>Inventory loading, product updates, and cost tracking</li>
            <li>Bulk price updates, margin alerts, cleanup tools, and CSV exports</li>
        </ul>
    `));
});

app.get("/privacy", (req, res) => {
    res.send(renderSimplePage("Privacy Policy", `
        <p>InventoryRite for Clover is designed to help Clover merchants manage products, prices, costs, and inventory workflow tools.</p>
        <h2>Data We Access</h2>
        <p>With merchant authorization, the app may access Clover merchant ID, employee ID, access token, product IDs, product names, prices, availability, and related inventory fields needed to operate the app.</p>
        <h2>Data We Store</h2>
        <p>The app may store merchant connection details and item cost values so profit, margin, and cleanup tools can work across sessions.</p>
        <h2>How Data Is Used</h2>
        <p>Data is used only to provide inventory management, bulk operations, margin review, smart pricing guidance, cleanup tools, and merchant support.</p>
        <h2>Contact</h2>
        <p>Questions can be sent to <a href="mailto:muheisenone@outlook.com">muheisenone@outlook.com</a>.</p>
    `));
});

app.get("/data-retention", (req, res) => {
    res.send(`
        <h1>InventoryRite Data Retention and Deletion Policy</h1>
        <p>InventoryRite stores only the merchant connection and product cost data needed to operate the app. Merchants may request deletion of stored app data by contacting support.</p>
        <p>When a merchant disconnects or requests deletion, InventoryRite will remove stored Clover connection tokens and merchant-specific app data unless retention is required for legal, fraud prevention, or accounting reasons.</p>
        <p>Support: muheisenone@outlook.com</p>
        <a href="/">Back</a>
    `);
});

app.get("/dmca", (req, res) => {
    res.send(`
        <h1>InventoryRite Copyright / DMCA Policy</h1>
        <p>If you believe content in InventoryRite infringes your copyright, contact support with the copyrighted work, the allegedly infringing material, your contact information, and a good-faith statement.</p>
        <p>Support: muheisenone@outlook.com</p>
        <a href="/">Back</a>
    `);
});

app.get("/terms", (req, res) => {
    res.send(renderSimplePage("Terms of Service", `
        <p>By using InventoryRite for Clover, merchants agree to use the app responsibly for product and inventory management workflows.</p>
        <h2>Merchant Responsibility</h2>
        <p>Merchants are responsible for reviewing all product, price, cost, and bulk update changes before saving them to Clover.</p>
        <h2>No Automatic Price Changes</h2>
        <p>Smart pricing and cleanup tools provide guidance. The app does not automatically overwrite Clover prices without merchant action and confirmation.</p>
        <h2>Service Availability</h2>
        <p>The app depends on Clover APIs, hosting availability, merchant permissions, and internet access. Temporary interruptions may occur.</p>
        <h2>Contact</h2>
        <p>Questions can be sent to <a href="mailto:muheisenone@outlook.com">muheisenone@outlook.com</a>.</p>
    `));
});

/*
|--------------------------------------------------------------------------
| DEVELOPER TOOLS ROUTE
|--------------------------------------------------------------------------
*/

app.get("/dev", (req, res) => {
    const connection = latestCloverConnection;

    res.send(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <title>InventoryRite Developer Tools</title>
    <style>
        body { font-family: Arial, Helvetica, sans-serif; background:#f5f7fb; margin:0; padding:30px; color:#111827; }
        .wrap { max-width: 980px; margin:0 auto; }
        .card { background:white; border:1px solid #e5e7eb; border-radius:18px; padding:22px; margin-bottom:16px; box-shadow:0 12px 35px rgba(15,23,42,.08); }
        h1 { margin-top:0; }
        pre { background:#0f172a; color:#e5e7eb; padding:18px; border-radius:14px; overflow:auto; }
        a { color:#15803d; font-weight:800; text-decoration:none; }
        .row { display:flex; justify-content:space-between; border-bottom:1px solid #e5e7eb; padding:10px 0; gap:20px; }
        .row:last-child { border-bottom:0; }
        .label { color:#64748b; }
        .value { font-weight:800; word-break:break-all; text-align:right; }


        /* ----------------------------------------------------------------
        | SIMPLIFIED MERCHANT UI - SIMPLE BY DEFAULT, ADVANCED ON DEMAND
        | Keeps all functionality but hides noisy panels until requested.
        ---------------------------------------------------------------- */

        .simple-hero {
            min-height: auto !important;
            padding: 24px 26px !important;
            align-items: center;
        }

        .simple-hero:after { display: none; }

        .simple-hero-copy { max-width: 720px; }

        .simple-hero h2 {
            font-size: 31px !important;
            line-height: 1.08;
            margin: 0;
        }

        .simple-hero p {
            font-size: 14px !important;
            max-width: 680px;
            margin-top: 9px;
        }

        .simple-hero-actions {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            justify-content: flex-end;
            position: relative;
            z-index: 2;
        }

        .simple-status-strip {
            border-color: #e5e7eb !important;
            background: #ffffff !important;
        }

        .inventory-command-center {
            box-shadow: none !important;
            border-color: #e5e7eb !important;
            background: #ffffff !important;
        }

        .command-search-actions .btn { min-width: 112px; }

        #merchantControlBar,
        #productivityHub,
        #operationsSummaryStrip,
        #lastActionStrip,
        #recentChangesPanel,
        #marginStatsRow,
        .merchant-hint {
            display: none !important;
        }

        body.show-advanced #merchantControlBar { display: flex !important; }
        body.show-advanced #productivityHub { display: grid !important; }
        body.show-advanced #operationsSummaryStrip { display: flex !important; }
        body.show-advanced #lastActionStrip { display: flex !important; }
        body.show-advanced #recentChangesPanel { display: block !important; }
        body.show-advanced #marginStatsRow { display: grid !important; }
        body.show-advanced .merchant-hint { display: block !important; }

        body.show-advanced #btnToggleAdvancedTop,
        body.show-advanced #btnHeroAdvanced {
            background: #111827;
            color: #ffffff;
            border-color: #111827;
        }

        .stats-row:first-of-type {
            margin-top: 4px;
        }

        .stat-box {
            box-shadow: none !important;
        }

        @media (max-width: 760px) {
            .simple-hero {
                flex-direction: column;
                align-items: flex-start;
            }

            .simple-hero-actions {
                width: 100%;
                justify-content: flex-start;
            }

            .simple-hero-actions .btn {
                flex: 1 1 140px;
            }
        }

    </style>
</head>
<body>
    <div class="wrap">
        <p><a href="/">&larr; Back to Inventory</a></p>
        <div class="card">
            <h1>Developer Tools</h1>
            <p>This page is for setup/support only. Merchants should use the main inventory page.</p>
        </div>

        <div class="card">
            <h2>Connection</h2>
            <div class="row"><div class="label">Connected</div><div class="value">${connection.connected ? "Yes" : "No"}</div></div>
            <div class="row"><div class="label">Merchant ID</div><div class="value">${safe(connection.merchant_id) || "Not detected"}</div></div>
            <div class="row"><div class="label">Employee ID</div><div class="value">${safe(connection.employee_id) || "Not detected"}</div></div>
            <div class="row"><div class="label">Token</div><div class="value">${formatTokenForDisplay(connection.access_token) || "Not saved"}</div></div>
            <div class="row"><div class="label">Environment</div><div class="value">${IS_PRODUCTION_CLOVER ? "Production" : "Sandbox"}</div></div>
            <div class="row"><div class="label">Database</div><div class="value">${USE_DATABASE ? "Connected" : "Demo memory mode"}</div></div>
            <div class="row"><div class="label">Connected At</div><div class="value">${safe(connection.connected_at) || "Not connected"}</div></div>
        </div>

        <div class="card">
            <h2>Routes</h2>
            <pre>/health
/app-status
/clover-connection
/clover-items
/clover-create-item
/clover-update-item/:itemId
/clover-delete-item/:itemId
/item-costs
/item-cost/:itemId</pre>
        </div>
    </div>
</body>
</html>`);
});

/*
|--------------------------------------------------------------------------
| PUBLIC APP STATUS ROUTE
|--------------------------------------------------------------------------
*/

app.get("/app-status", (req, res) => {
    res.json({
        success: true,
        app: "InventoryRite Clover Connector",
        status: "online",
        environment: IS_PRODUCTION_CLOVER ? "production" : "sandbox",
        connected: latestCloverConnection.connected,
        hasMerchant: !!latestCloverConnection.merchant_id,
        connectedAt: latestCloverConnection.connected_at || null,
        databaseEnabled: USE_DATABASE
    });
});

/*
|--------------------------------------------------------------------------
| 404
|--------------------------------------------------------------------------
*/

app.use((req, res) => {
    res.status(404).json({
        success: false,
        message: "Route not found.",
        path: req.originalUrl
    });
});

process.on("SIGTERM", async () => {
    console.log("SIGTERM received. Closing server resources...");
    if (dbPool) await dbPool.end();
    process.exit(0);
});

process.on("SIGINT", async () => {
    console.log("SIGINT received. Closing server resources...");
    if (dbPool) await dbPool.end();
    process.exit(0);
});

initDatabase()
    .catch((error) => {
        console.error("Database initialization warning:", error.message);
    })
    .finally(() => {
        app.listen(PORT, () => {
            console.log(`Server running on port ${PORT}`);
            console.log(`Database mode: ${USE_DATABASE ? "PostgreSQL" : "Demo memory only"}`);
        });
    });