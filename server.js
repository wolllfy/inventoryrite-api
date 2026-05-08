const express = require("express");
const cors = require("cors");
const axios = require("axios");
require("dotenv").config();

let Pool = null;
try {
    ({ Pool } = require("pg"));
} catch (error) {
    Pool = null;
}

const app = express();

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const PORT = process.env.PORT || 3000;

const CLOVER_CLIENT_ID = process.env.CLOVER_CLIENT_ID?.trim();
const CLOVER_CLIENT_SECRET = process.env.CLOVER_CLIENT_SECRET?.trim();

const APP_BASE_URL = (process.env.APP_BASE_URL || "https://inventoryrite-api.onrender.com").replace(/\/$/, "");
const REDIRECT_URI = (process.env.REDIRECT_URI || `${APP_BASE_URL}/`).trim();

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

const DATABASE_URL = process.env.DATABASE_URL?.trim() || "";
const USE_DATABASE = !!DATABASE_URL && !!Pool;

const dbPool = USE_DATABASE
    ? new Pool({
        connectionString: DATABASE_URL,
        ssl: process.env.PGSSLMODE === "disable" ? false : { rejectUnauthorized: false }
    })
    : null;

const cloverApi = axios.create({
    timeout: REQUEST_TIMEOUT_MS
});

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
            connected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
    `);

    await dbPool.query(`
        CREATE TABLE IF NOT EXISTS item_costs (
            merchant_id TEXT NOT NULL,
            item_id TEXT NOT NULL,
            cost_cents INTEGER NOT NULL DEFAULT 0,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            PRIMARY KEY (merchant_id, item_id)
        );
    `);

    const lastConnection = await dbPool.query(`
        SELECT merchant_id, employee_id, access_token, connected_at
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
            access_token: row.access_token || "",
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
        connected_at: connection.connected_at || new Date().toISOString()
    };

    if (!USE_DATABASE || !dbPool || !latestCloverConnection.merchant_id || !latestCloverConnection.access_token) {
        return latestCloverConnection;
    }

    await dbPool.query(
        `INSERT INTO merchant_connections (merchant_id, employee_id, access_token, connected_at, updated_at)
         VALUES ($1, $2, $3, $4, NOW())
         ON CONFLICT (merchant_id)
         DO UPDATE SET
            employee_id = EXCLUDED.employee_id,
            access_token = EXCLUDED.access_token,
            connected_at = EXCLUDED.connected_at,
            updated_at = NOW();`,
        [
            latestCloverConnection.merchant_id,
            latestCloverConnection.employee_id,
            latestCloverConnection.access_token,
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

function getConnectionFromRequest(req) {
    const tokenFromQuery = req.query.token || req.body?.token || "";
    const merchantFromQuery = req.query.merchantId || req.body?.merchantId || "";

    return {
        accessToken: tokenFromQuery || latestCloverConnection.access_token,
        merchantId: merchantFromQuery || latestCloverConnection.merchant_id
    };
}

function cloverHeaders(accessToken) {
    return {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json"
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

/*
|--------------------------------------------------------------------------
| UI
|--------------------------------------------------------------------------
*/

function renderDashboard(options = {}) {
    const merchantId = options.merchant_id || latestCloverConnection.merchant_id || "";
    const employeeId = options.employee_id || latestCloverConnection.employee_id || "";
    const accessToken = options.access_token || latestCloverConnection.access_token || "";
    const connected = !!accessToken || latestCloverConnection.connected;
    const connectedAt = options.connected_at || latestCloverConnection.connected_at || "";

    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>InventoryRite for Clover</title>
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

        .wrap { width: 100%; max-width: 1460px; margin: 26px auto; padding: 0 18px 50px; }

        .hero {
            background: rgba(255,255,255,0.96);
            border: 1px solid var(--line);
            border-radius: var(--radius);
            box-shadow: var(--shadow);
            padding: 28px;
            margin-bottom: 18px;
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            gap: 18px;
            overflow: hidden;
            position: relative;
        }

        .hero:after {
            content: "";
            position: absolute;
            width: 260px;
            height: 260px;
            border-radius: 50%;
            right: -120px;
            top: -120px;
            background: rgba(34, 197, 94, 0.13);
            pointer-events: none;
        }

        .eyebrow {
            color: var(--green);
            font-weight: 900;
            letter-spacing: .08em;
            text-transform: uppercase;
            font-size: 12px;
            margin-bottom: 9px;
        }

        .hero h2 {
            margin: 0;
            font-size: 34px;
            line-height: 1.08;
            letter-spacing: -0.035em;
            max-width: 760px;
        }

        .hero p {
            margin: 12px 0 0;
            color: var(--muted);
            line-height: 1.55;
            max-width: 720px;
            font-size: 15px;
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
            background: #f8fafc;
            border: 1px solid var(--line);
            border-radius: 16px;
            padding: 16px;
            margin: 0 0 16px;
        }

        .add-panel.show { display: block; }

        .add-grid {
            display: grid;
            grid-template-columns: 1fr 180px auto;
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
        | ALWAYS-VISIBLE MERCHANT CONTROL BAR
        | These are the money features merchants see immediately.
        ---------------------------------------------------------------- */

        .merchant-control-bar {
            display: grid;
            grid-template-columns: 1fr auto;
            gap: 14px;
            align-items: center;
            background: linear-gradient(135deg, #0f172a 0%, #111827 52%, #1f2937 100%);
            border: 1px solid rgba(255,255,255,0.10);
            border-radius: 18px;
            padding: 14px;
            margin: 0 0 16px;
            box-shadow: 0 16px 40px rgba(15, 23, 42, 0.14);
        }

        .merchant-control-left {
            min-width: 0;
        }

        .merchant-control-title {
            color: #ffffff;
            font-size: 15px;
            font-weight: 900;
            margin-bottom: 3px;
        }

        .merchant-control-subtitle {
            color: #cbd5e1;
            font-size: 12px;
            font-weight: 700;
            line-height: 1.4;
        }

        .merchant-control-buttons {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            justify-content: flex-end;
        }

        .money-btn {
            min-height: 38px;
            padding: 9px 12px;
            border-radius: 12px;
            font-size: 12px;
            border: 1px solid rgba(255,255,255,0.12);
            box-shadow: none;
            white-space: nowrap;
        }

        .btn-orange { background: #f97316; color: white; }
        .btn-cyan { background: #0891b2; color: white; }
        .btn-black { background: #020617; color: white; }
        .btn-purple { background: #7c3aed; color: white; }
        .btn-red-strong { background: #dc2626; color: white; }
        .btn-slate { background: #475569; color: white; }
        .btn-green-strong { background: #16a34a; color: white; }

        .active-money-filter {
            outline: 3px solid rgba(255,255,255,0.38);
            transform: translateY(-1px);
        }

        .feature-panel {
            display: grid;
            gap: 10px;
            margin-top: 14px;
        }

        .feature-row {
            background: #f8fafc;
            border: 1px solid #e5e7eb;
            border-radius: 14px;
            padding: 11px 12px;
            display: grid;
            grid-template-columns: 1fr auto;
            gap: 10px;
            align-items: center;
            font-size: 13px;
        }

        .feature-row strong {
            display: block;
            color: #0f172a;
            margin-bottom: 2px;
        }

        .feature-row span {
            color: #64748b;
            line-height: 1.35;
        }

        .feature-metric {
            font-weight: 900;
            color: #111827;
            white-space: nowrap;
        }

        .modal-wide {
            max-width: 720px;
        }

        @media (max-width: 980px) {
            .hero, .stats-row, .add-grid { grid-template-columns: 1fr; }
            .hero { flex-direction: column; }
            .hero h2 { font-size: 28px; }
            .topbar { align-items: flex-start; gap: 14px; flex-direction: column; }
            .table-top { flex-direction: column; }
            .toolbar { width: 100%; justify-content: flex-start; }
            .search-input { width: 100%; min-width: 100%; max-width: 100%; }
            .bulk-controls { flex-direction: column; align-items: flex-start; }
            .merchant-control-bar { grid-template-columns: 1fr; }
            .merchant-control-buttons { justify-content: flex-start; }
            .stats-row { grid-template-columns: 1fr 1fr; }
            th, td { padding: 10px 6px; font-size: 12px; }
            .btn-small { padding: 7px 7px; font-size: 11px; }
            .row-actions { gap: 5px; }
        }

        @media (max-width: 700px) {
            .stats-row { grid-template-columns: 1fr; }
            .wrap { padding: 0 10px 40px; }
            .inventory-card { padding: 14px; }
            .hero { padding: 20px; }
            .hero h2 { font-size: 24px; }
            .table-wrap { border-radius: 12px; }
            th, td { padding: 9px 5px; font-size: 11px; }
            .check-col { width: 6%; }
            .name-col { width: 40%; }
            .money-col { width: 14%; }
            .metric-col { width: 10%; }
            .actions-col { width: 16%; }
            .row-actions .btn-small { flex-basis: 100%; }
        }
    </style>
</head>
<body>

    <div class="topbar">
        <div class="brand">
            <div class="logo">IR</div>
            <div>
                <h1>InventoryRite for Clover</h1>
                <p>Product and inventory manager for Clover merchants</p>
            </div>
        </div>

        <div class="badge ${connected ? "connected" : "disconnected"}" id="topBadge">
            ${connected ? "Connected" : "Connection Required"}
        </div>
    </div>

    <main class="wrap">

        ${connected ? `
        <section class="hero">
            <div>
                <div class="eyebrow">Clover Inventory</div>
                <h2>Manage your Clover products in one clean workspace.</h2>
                <p>Search products, update names and prices, create new items, and remove products from your Clover inventory.</p>
            </div>

            <div class="hero-actions">
                <button id="btnRefreshInventoryTop" type="button" class="btn btn-secondary">Refresh Inventory</button>
                <button id="btnToggleBulkTop" type="button" class="btn btn-amber">⚡ Bulk Price Update</button>
                <button id="btnToggleAddTop" type="button" class="btn btn-primary">Add Product</button>
            </div>
        </section>

        <section class="card inventory-card">
            <div class="table-top">
                <div>
                    <h3>Products</h3>
                    <p>Loaded Clover products appear below. Edit a name or price, then click Save.</p>
                    <div class="sync-note" id="lastSyncNote">Last synced: Not yet</div>
                </div>
                <div class="toolbar">
                    <input id="inventorySearch" class="search-input" type="text" placeholder="Search product, SKU, or Clover ID..." />
                    <button id="btnRefreshInventory" type="button" class="btn btn-secondary">Refresh</button>
                    <button id="btnToggleBulk" type="button" class="btn btn-amber">⚡ Bulk Price Update</button>
                    <button id="btnToggleAdd" type="button" class="btn btn-primary">Add Product</button>
                </div>
            </div>

            <!-- ADD PRODUCT PANEL (unchanged) -->
            <div class="add-panel" id="addPanel">
                <div class="add-grid">
                    <div>
                        <label for="itemName">Product Name</label>
                        <input id="itemName" type="text" value="New Clover Item" />
                    </div>
                    <div>
                        <label for="itemPrice">Price Cents</label>
                        <input id="itemPrice" type="number" value="199" />
                    </div>
                    <button id="btnCreateItem" type="button" class="btn btn-primary">Create Product</button>
                </div>
            </div>

            <!-- BULK PRICE UPDATE PANEL -->
            <div class="bulk-panel" id="bulkPanel">
                <div class="bulk-panel-header">
                    <div class="bulk-panel-title">
                        ⚡ Bulk Price Update &mdash;
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
                                ▲ Increase by %
                            </button>
                            <button id="btnBulkDecrease" type="button" class="btn btn-small btn-bulk-decrease">
                                ▼ Decrease by %
                            </button>
                            <button id="btnBulkClearPanel" type="button" class="btn btn-small btn-light">
                                Clear Selection
                            </button>
                        </div>
                    </div>
                </div>
                <div class="bulk-progress" id="bulkProgress">
                    <div class="bulk-progress-bar" id="bulkProgressBar"></div>
                </div>
                <div class="bulk-progress-label" id="bulkProgressLabel"></div>
            </div>



            <!-- ALWAYS-VISIBLE MERCHANT CONTROL BAR -->
            <div class="merchant-control-bar" id="merchantControlBar">
                <div class="merchant-control-left">
                    <div class="merchant-control-title">Merchant Control Bar</div>
                    <div class="merchant-control-subtitle">Profit, low stock, CSV tools, reorder planning, and activity tracking in one place.</div>
                </div>
                <div class="merchant-control-buttons">
                    <button id="btnAllProducts" type="button" class="btn money-btn btn-slate">All Products</button>
                    <button id="btnLowStock" type="button" class="btn money-btn btn-orange">Low Stock</button>
                    <button id="btnReorder" type="button" class="btn money-btn btn-cyan">Reorder</button>
                    <button id="btnExportCsv" type="button" class="btn money-btn btn-black">Export CSV</button>
                    <button id="btnImportCsv" type="button" class="btn money-btn btn-green-strong">Import CSV</button>
                    <button id="btnPriceRules" type="button" class="btn money-btn btn-purple">Price Rules</button>
                    <button id="btnProfitAlerts" type="button" class="btn money-btn btn-red-strong">Profit Alerts</button>
                    <button id="btnActivityLog" type="button" class="btn money-btn btn-slate">Activity Log</button>
                </div>
            </div>

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
                    <div class="stat-value" id="statAvgMargin">—</div>
                </div>
                <div class="stat-box">
                    <div class="stat-label">Best Margin Item</div>
                    <div class="stat-value" id="statBestMargin">—</div>
                </div>
                <div class="stat-box">
                    <div class="stat-label">Lowest Margin Item</div>
                    <div class="stat-value" id="statLowestMargin">—</div>
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
            InventoryRite for Clover · Process Rite Inc · <a class="dev-link" href="/dev">Developer tools</a>
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
            <p>Extra Clover fields and profit details are kept here so the main product table stays clean with no left/right scroll.</p>
            <div class="detail-grid" id="detailsGrid"></div>
            <div class="modal-actions">
                <button id="detailsClose" type="button" class="btn btn-light">Close</button>
            </div>
        </div>
    </div>



    <div class="modal-backdrop" id="featureModal">
        <div class="modal modal-wide">
            <h3 id="featureTitle">Feature</h3>
            <p id="featureMessage">Feature details.</p>
            <div class="feature-panel" id="featurePanel"></div>
            <div class="modal-actions">
                <button id="featureClose" type="button" class="btn btn-light">Close</button>
            </div>
        </div>
    </div>

    <script>
    (function () {
        window.addEventListener("error", function (event) {
            try {
                var wrap = document.getElementById("toastWrap");
                if (wrap) {
                    var toast = document.createElement("div");
                    toast.className = "toast error";
                    toast.textContent = "Page script error: " + (event && event.message ? event.message : "Unknown error");
                    wrap.appendChild(toast);
                }
            } catch (e) {}
            console.error("InventoryRite page error", event);
        });

        var embeddedConnection = {
            connected: ${connected ? "true" : "false"},
            merchant_id: ${JSON.stringify(merchantId)},
            employee_id: ${JSON.stringify(employeeId)},
            access_token: ${JSON.stringify(accessToken)},
            connected_at: ${JSON.stringify(connectedAt)}
        };

        var loadedItems = [];
        var itemCosts = {};
        var lastUpdatedItemId = "";
        var bulkUpdatedItemIds = [];
        var isBusy = false;
        var pendingConfirmAction = null;
        var activeMoneyFilter = "all";
        var activityLog = [];

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
            return embeddedConnection.access_token || "";
        }

        function getMerchantId() {
            return embeddedConnection.merchant_id || "";
        }

        function formatCurrencyFromCents(cents) {
            var value = Number(cents || 0) / 100;
            return value.toLocaleString(undefined, { style: "currency", currency: "USD" });
        }

        function formatDateFromClover(value) {
            if (!value) return "—";
            try {
                return new Date(Number(value)).toLocaleString();
            } catch (e) {
                return "—";
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

        function setButtonText(id, text) {
            var btn = byId(id);
            if (btn) btn.textContent = text;
        }

        function updateLastSyncNote() {
            var note = byId("lastSyncNote");
            if (!note) return;
            note.textContent = "Last synced: " + new Date().toLocaleString();
        }

        function setButtonsDisabled(disabled) {
            var buttons = document.querySelectorAll("button");
            buttons.forEach(function (btn) {
                if (btn.id === "confirmCancel" || btn.id === "confirmYes" || btn.id === "detailsClose" || btn.id === "featureClose") return;
                if (btn.id === "btnRefreshInventory" || btn.id === "btnRefreshInventoryTop") return;
                if (btn.id === "btnToggleAdd" || btn.id === "btnToggleAddTop" || btn.id === "btnToggleBulk" || btn.id === "btnToggleBulkTop") return;
                if (btn.id === "btnAllProducts" || btn.id === "btnLowStock" || btn.id === "btnReorder" || btn.id === "btnExportCsv" || btn.id === "btnImportCsv" || btn.id === "btnPriceRules" || btn.id === "btnProfitAlerts" || btn.id === "btnActivityLog") return;
                btn.disabled = disabled;
            });
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

            if (!token || !merchantId) {
                showToast("Please connect Clover first.", "error");
                return null;
            }

            return { token: token, merchantId: merchantId };
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



        function getQuantityValue(item) {
            var possible = [item.quantity, item.stockCount, item.stock, item.availableQuantity, item.onHand, item.inventoryCount];
            for (var i = 0; i < possible.length; i++) {
                var n = Number(possible[i]);
                if (!Number.isNaN(n) && Number.isFinite(n)) return n;
            }
            return null;
        }

        function getLowStockThreshold() {
            return 5;
        }

        function isLowStockItem(item) {
            var q = getQuantityValue(item);
            return q !== null && q <= getLowStockThreshold();
        }

        function isProfitAlertItem(item) {
            var price = Number(item.price || 0);
            var cost = getCostCents(item.id || "");
            if (price <= 0 || cost <= 0) return false;
            var margin = calculateMargin(price, cost);
            return (price - cost) < 0 || (margin !== null && margin < 30);
        }

        function addActivity(message) {
            activityLog.unshift({
                message: message,
                at: new Date().toLocaleString()
            });
            activityLog = activityLog.slice(0, 25);
        }

        function setActiveMoneyFilter(filterName) {
            activeMoneyFilter = filterName || "all";
            var ids = ["btnAllProducts", "btnLowStock", "btnProfitAlerts"];
            ids.forEach(function (id) {
                var el = byId(id);
                if (el) el.classList.remove("active-money-filter");
            });
            if (activeMoneyFilter === "all" && byId("btnAllProducts")) byId("btnAllProducts").classList.add("active-money-filter");
            if (activeMoneyFilter === "lowStock" && byId("btnLowStock")) byId("btnLowStock").classList.add("active-money-filter");
            if (activeMoneyFilter === "profitAlerts" && byId("btnProfitAlerts")) byId("btnProfitAlerts").classList.add("active-money-filter");
            renderItems(loadedItems);
        }

        function openFeatureModal(title, message, rows) {
            var modal = byId("featureModal");
            var titleEl = byId("featureTitle");
            var messageEl = byId("featureMessage");
            var panel = byId("featurePanel");

            if (titleEl) titleEl.textContent = title || "Feature";
            if (messageEl) messageEl.textContent = message || "";
            if (panel) {
                panel.innerHTML = "";
                (rows || []).forEach(function (row) {
                    var div = document.createElement("div");
                    div.className = "feature-row";
                    div.innerHTML =
                        "<div><strong>" + escapeHtml(row.title || "") + "</strong><span>" + escapeHtml(row.text || "") + "</span></div>" +
                        "<div class='feature-metric'>" + escapeHtml(row.metric || "") + "</div>";
                    panel.appendChild(div);
                });
            }
            if (modal) modal.classList.add("show");
        }

        function closeFeatureModal() {
            var modal = byId("featureModal");
            if (modal) modal.classList.remove("show");
        }

        function exportInventoryCsv() {
            if (!loadedItems.length) {
                showToast("Load inventory first, then export CSV.", "error");
                return;
            }

            var headers = ["Name", "Clover ID", "SKU/Code", "Price", "Cost", "Profit Per Unit", "Margin %", "Available", "Hidden"];
            var rows = loadedItems.map(function (item) {
                var price = Number(item.price || 0);
                var cost = getCostCents(item.id || "");
                var margin = calculateMargin(price, cost);
                var sku = item.sku || item.code || item.productCode || "";
                return [
                    item.name || "",
                    item.id || "",
                    sku,
                    (price / 100).toFixed(2),
                    (cost / 100).toFixed(2),
                    ((price - cost) / 100).toFixed(2),
                    margin === null ? "" : margin.toFixed(1),
                    item.available === false ? "No" : "Yes",
                    item.hidden ? "Yes" : "No"
                ];
            });

            function csvEscape(value) {
                return '"' + String(value || "").replaceAll('"', '""') + '"';
            }

            var csv = [headers].concat(rows).map(function (row) {
                return row.map(csvEscape).join(",");
            }).join("\n");

            var blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
            var url = URL.createObjectURL(blob);
            var a = document.createElement("a");
            a.href = url;
            a.download = "inventoryrite-clover-products.csv";
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            addActivity("Exported product CSV");
            showToast("CSV exported successfully.", "success");
        }

        function showLowStockReport() {
            var qtyKnown = loadedItems.filter(function (item) { return getQuantityValue(item) !== null; });
            var low = loadedItems.filter(isLowStockItem);

            if (!qtyKnown.length) {
                openFeatureModal(
                    "Low Stock",
                    "Clover did not return quantity fields for these products from the current item response. The button is ready; the next step is adding Clover inventory quantity lookup.",
                    [
                        { title: "Current products loaded", text: "Products are loaded, but quantity was not included in this response.", metric: String(loadedItems.length) },
                        { title: "Recommended next build", text: "Add Clover inventory endpoint lookup so this dashboard can show exact low-stock items.", metric: "Next" }
                    ]
                );
                return;
            }

            setActiveMoneyFilter("lowStock");
            openFeatureModal(
                "Low Stock",
                "Products at or below " + getLowStockThreshold() + " units are now filtered in the table.",
                low.slice(0, 10).map(function (item) {
                    return { title: item.name || "Unnamed Product", text: "This item is at or below your low-stock threshold.", metric: String(getQuantityValue(item)) + " left" };
                })
            );
        }

        function showProfitAlerts() {
            var alerts = loadedItems.filter(isProfitAlertItem).sort(function (a, b) {
                return (calculateMargin(Number(a.price || 0), getCostCents(a.id || "")) || 0) - (calculateMargin(Number(b.price || 0), getCostCents(b.id || "")) || 0);
            });

            setActiveMoneyFilter("profitAlerts");
            openFeatureModal(
                "Profit Alerts",
                alerts.length ? "Low-margin and below-cost products are now filtered in the table." : "No profit alerts found. Add product costs to unlock stronger margin warnings.",
                alerts.slice(0, 10).map(function (item) {
                    var price = Number(item.price || 0);
                    var cost = getCostCents(item.id || "");
                    var margin = calculateMargin(price, cost);
                    return {
                        title: item.name || "Unnamed Product",
                        text: "Price " + formatCurrencyFromCents(price) + " · Cost " + formatCurrencyFromCents(cost),
                        metric: margin === null ? "No margin" : margin.toFixed(1) + "%"
                    };
                })
            );
        }

        function showComingSoonFeature(type) {
            var data = {
                reorder: {
                    title: "Smart Reorder",
                    message: "This is the subscription feature: it will suggest what to reorder before the merchant runs out.",
                    rows: [
                        { title: "Reorder Suggestions", text: "Builds a list of products that need restocking.", metric: "Premium" },
                        { title: "Supplier Workflow", text: "Future version can create a purchase order from selected items.", metric: "Sticky" }
                    ]
                },
                importCsv: {
                    title: "Import CSV",
                    message: "This will let merchants bulk-create or bulk-update products from a spreadsheet.",
                    rows: [
                        { title: "Mass Updates", text: "Update hundreds of product names, prices, and costs at once.", metric: "Time Saver" },
                        { title: "Migration Tool", text: "Useful when moving from another POS or spreadsheet.", metric: "Sales Tool" }
                    ]
                },
                priceRules: {
                    title: "Price Rules",
                    message: "This will let merchants create repeatable pricing rules instead of manual edits.",
                    rows: [
                        { title: "Category Markups", text: "Example: increase all drinks by 8% or round prices to .99.", metric: "Automation" },
                        { title: "Margin Protection", text: "Warn before a product is priced under target margin.", metric: "Profit" }
                    ]
                },
                activityLog: {
                    title: "Activity Log",
                    message: "This becomes the trust feature: who changed what, when, and what happened.",
                    rows: activityLog.length ? activityLog.map(function (log) {
                        return { title: log.message, text: log.at, metric: "Logged" };
                    }) : [
                        { title: "No activity yet", text: "Changes like exports, saves, deletes, and bulk updates will appear here.", metric: "Ready" },
                        { title: "Future upgrade", text: "Store the audit trail in Postgres so merchants never lose history.", metric: "Sticky" }
                    ]
                }
            };

            var selected = data[type];
            openFeatureModal(selected.title, selected.message, selected.rows);
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

            if (statLoaded) statLoaded.textContent = String(loaded);
            if (statVisible) statVisible.textContent = String(visible);
            if (statAvailable) statAvailable.textContent = String(available);
            if (statValue) statValue.textContent = formatCurrencyFromCents(totalCents);
            if (statAvgMargin) statAvgMargin.textContent = avgMargin === null ? "—" : avgMargin.toFixed(1) + "%";
            if (statBestMargin) statBestMargin.textContent = best ? best.name.substring(0, 18) + " · " + best.margin.toFixed(1) + "%" : "—";
            if (statLowestMargin) statLowestMargin.textContent = lowest ? lowest.name.substring(0, 18) + " · " + lowest.margin.toFixed(1) + "%" : "—";
            if (statBelowCost) statBelowCost.textContent = String(belowCost);
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
                dirWord + " prices by " + pct + "% for " + selectedIds.length + " product(s). This cannot be undone.",
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
                        "/clover-update-item/" + encodeURIComponent(itemId) +
                        "?token=" + encodeURIComponent(connection.token) +
                        "&merchantId=" + encodeURIComponent(connection.merchantId),
                        {
                            method: "POST",
                            headers: { "Content-Type": "application/json" },
                            body: JSON.stringify({ name: item.name || "", price: newCents })
                        }
                    );
                    successCount++;
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

            if (failCount === 0) {
                showToast("Bulk update complete: " + successCount + " price(s) " + dirLabel + " by " + pct + "%.", "success");
                addActivity("Bulk price update: " + successCount + " product(s) " + dirLabel + " by " + pct + "%");
            } else {
                showToast("Bulk update: " + successCount + " succeeded, " + failCount + " failed.", failCount > 0 && successCount === 0 ? "error" : "info");
            }

            clearSelection();
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

            var filtered = (items || []).filter(function (item) {
                if (!search) return true;
                var sku = item.sku || item.code || item.productCode || "";
                var haystack = [item.name || "", sku, item.id || ""].join(" ").toLowerCase();
                return haystack.indexOf(search) >= 0;
            }).filter(function (item) {
                if (activeMoneyFilter === "lowStock") return isLowStockItem(item);
                if (activeMoneyFilter === "profitAlerts") return isProfitAlertItem(item);
                return true;
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
                    'Try a different search, clear filters, or click All Products.' +
                    '</td></tr>';
                syncBulkUI();
                return;
            }

            filtered.forEach(function (item) {
                var row = document.createElement("tr");
                var sku = item.sku || item.code || item.productCode || "—";
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

                if (isSelected) {
                    row.classList.add("row-selected");
                }

                row.innerHTML =
                    "<td class='col-check'><input type='checkbox' data-item-id='" + escapeHtml(itemId) + "' " + (isSelected ? "checked" : "") + " /></td>" +
                    "<td class='product-name-cell'><input class='name-input' data-name-for='" + escapeHtml(itemId) + "' value='" + escapeHtml(itemName) + "' /></td>" +
                    "<td><input class='small-input' data-price-for='" + escapeHtml(itemId) + "' value='" + escapeHtml(priceDollars) + "' /></td>" +
                    "<td><input class='small-input' data-cost-for='" + escapeHtml(itemId) + "' value='" + escapeHtml(costDollars) + "' title='Your cost of goods. Saves to InventoryRite and attempts to sync to Clover.' /></td>" +
                    "<td>" + getMarginPill(priceCents, costCents) + "</td>" +
                    "<td><div class='row-actions'>" +
                        "<button type='button' class='btn btn-secondary btn-small icon-action' title='Save product' aria-label='Save product' data-action='save' data-id='" + escapeHtml(itemId) + "'>✓</button>" +
                        "<button type='button' class='btn btn-light btn-small icon-action' title='View details' aria-label='View details' data-action='details' data-id='" + escapeHtml(itemId) + "'>i</button>" +
                        "<button type='button' class='btn btn-danger btn-small icon-action' title='Delete product' aria-label='Delete product' data-action='delete' data-id='" + escapeHtml(itemId) + "' data-name='" + escapeHtml(itemName) + "'>×</button>" +
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
                    saveItemCost(e.target.getAttribute("data-cost-for"), e.target.value);
                });
                input.addEventListener("keydown", function (e) {
                    if (e.key === "Enter") {
                        e.preventDefault();
                        e.target.blur();
                    }
                });
            });

            syncBulkUI();
        }

        async function fetchJson(url, options) {
            options = options || {};
            var controller = new AbortController();
            var timer = setTimeout(function () { controller.abort(); }, 30000);
            options.signal = controller.signal;

            var response;
            try {
                response = await fetch(url, options);
            } catch (networkError) {
                clearTimeout(timer);
                if (networkError && networkError.name === "AbortError") {
                    throw new Error("Request timed out. Refresh and try again.");
                }
                throw networkError;
            }
            clearTimeout(timer);
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

        function openConfirm(title, message, onConfirm) {
            pendingConfirmAction = onConfirm;

            var modal = byId("confirmModal");
            var titleEl = byId("confirmTitle");
            var messageEl = byId("confirmMessage");

            if (titleEl) titleEl.textContent = title || "Confirm Action";
            if (messageEl) messageEl.textContent = message || "Are you sure?";
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

            var sku = item.sku || item.code || item.productCode || "—";
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
                    "<div class='detail-label'>Clover ID</div><div class='detail-value'>" + escapeHtml(item.id || "—") + "</div>" +
                    "<div class='detail-label'>Available</div><div class='detail-value'>" + escapeHtml(available) + "</div>" +
                    "<div class='detail-label'>Hidden</div><div class='detail-value'>" + escapeHtml(hidden) + "</div>" +
                    "<div class='detail-label'>Revenue Item</div><div class='detail-value'>" + escapeHtml(revenue) + "</div>" +
                    "<div class='detail-label'>Modified</div><div class='detail-value'>" + escapeHtml(formatDateFromClover(item.modifiedTime)) + "</div>" +
                    "<div class='detail-label'>Price</div><div class='detail-value'>" + escapeHtml(formatCurrencyFromCents(priceCents)) + "</div>" +
                    "<div class='detail-label'>Cost</div><div class='detail-value'>" + escapeHtml(formatCurrencyFromCents(costCents)) + "</div>" +
                    "<div class='detail-label'>Profit / Unit</div><div class='detail-value'>" + escapeHtml(formatCurrencyFromCents(profitCents)) + "</div>" +
                    "<div class='detail-label'>Margin</div><div class='detail-value'>" + escapeHtml(margin === null ? "—" : margin.toFixed(1) + "%") + "</div>";
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
                    "/item-cost/" + encodeURIComponent(itemId) +
                    "?token=" + encodeURIComponent(connection.token) +
                    "&merchantId=" + encodeURIComponent(connection.merchantId),
                    {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ costCents: costCents })
                    }
                );

                itemCosts[itemId] = costCents;
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

                var data = await fetchJson(
                    "/clover-items?token=" + encodeURIComponent(connection.token) +
                    "&merchantId=" + encodeURIComponent(connection.merchantId)
                );

                var costData = await fetchJson(
                    "/item-costs?token=" + encodeURIComponent(connection.token) +
                    "&merchantId=" + encodeURIComponent(connection.merchantId)
                );

                loadedItems = data.data && data.data.elements ? data.data.elements : [];
                itemCosts = costData.costs || {};

                loadedItems.forEach(function (item) {
                    if (!item || !item.id) return;
                    if ((itemCosts[item.id] === undefined || Number(itemCosts[item.id]) === 0) && item.cost !== undefined && item.cost !== null) {
                        itemCosts[item.id] = Number(item.cost || 0);
                    }
                });

                activeMoneyFilter = activeMoneyFilter || "all";
                renderItems(loadedItems);
                setActiveMoneyFilter(activeMoneyFilter);
                updateLastSyncNote();
                showToast("Inventory loaded: " + loadedItems.length + " product(s).", "success");
            } catch (error) {
                showToast(error && error.message ? error.message : "Unable to load inventory.", "error");
            } finally {
                setButtonText("btnRefreshInventory", "Refresh");
                setButtonText("btnRefreshInventoryTop", "Refresh Inventory");
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
                    "/clover-create-item?token=" + encodeURIComponent(connection.token) +
                    "&merchantId=" + encodeURIComponent(connection.merchantId),
                    {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ name: name, price: Number(price) })
                    }
                );

                lastUpdatedItemId = data && data.data && data.data.id ? data.data.id : "";
                showToast("Product created successfully.", "success");
                addActivity("Created product: " + name);

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

                var name = nameBox && nameBox.value ? nameBox.value.trim() : "";
                var priceCents = priceToCentsFromDollarsString(priceBox && priceBox.value ? priceBox.value : "0");

                if (!name) {
                    showToast("Product name cannot be empty.", "error");
                    return;
                }

                if (priceCents === null) {
                    showToast("Price must be a valid dollar amount.", "error");
                    return;
                }

                startBusy();

                await fetchJson(
                    "/clover-update-item/" + encodeURIComponent(itemId) +
                    "?token=" + encodeURIComponent(connection.token) +
                    "&merchantId=" + encodeURIComponent(connection.merchantId),
                    {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ name: name, price: priceCents })
                    }
                );

                lastUpdatedItemId = itemId;
                showToast("Product updated.", "success");
                addActivity("Updated product: " + name);

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
                    "/clover-delete-item/" + encodeURIComponent(itemId) +
                    "?token=" + encodeURIComponent(connection.token) +
                    "&merchantId=" + encodeURIComponent(connection.merchantId),
                    { method: "POST" }
                );

                showToast("Product deleted.", "success");
                addActivity("Deleted product from Clover");

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

        /*
        |------------------------------------------------------------------
        | EVENT BINDINGS
        |------------------------------------------------------------------
        */

        bind("btnRefreshInventoryTop", "click", loadItems);
        bind("btnRefreshInventory", "click", loadItems);
        bind("btnToggleAddTop", "click", toggleAddPanel);
        bind("btnToggleAdd", "click", toggleAddPanel);
        bind("btnToggleBulkTop", "click", toggleBulkPanel);
        bind("btnToggleBulk", "click", toggleBulkPanel);
        bind("btnCreateItem", "click", createItem);
        bind("inventorySearch", "input", function () { renderItems(loadedItems); });
        bind("btnAllProducts", "click", function () { setActiveMoneyFilter("all"); showToast("Showing all products.", "info"); });
        bind("btnLowStock", "click", showLowStockReport);
        bind("btnReorder", "click", function () { showComingSoonFeature("reorder"); });
        bind("btnExportCsv", "click", exportInventoryCsv);
        bind("btnImportCsv", "click", function () { showComingSoonFeature("importCsv"); });
        bind("btnPriceRules", "click", function () { showComingSoonFeature("priceRules"); });
        bind("btnProfitAlerts", "click", showProfitAlerts);
        bind("btnActivityLog", "click", function () { showComingSoonFeature("activityLog"); });
        bind("featureClose", "click", closeFeatureModal);


        bind("confirmCancel", "click", closeConfirm);
        bind("confirmYes", "click", function () {
            var action = pendingConfirmAction;
            closeConfirm();
            if (typeof action === "function") action();
        });
        bind("detailsClose", "click", closeItemDetails);

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
                if (event.target === featureModal) closeFeatureModal();
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

        if (embeddedConnection.connected && embeddedConnection.access_token && embeddedConnection.merchant_id) {
            loadItems();
        }
    })();
    </script>

</body>
</html>`;
}

/*
|--------------------------------------------------------------------------
| ROOT + CLOVER CALLBACK HANDLER
|--------------------------------------------------------------------------
*/

app.get("/", async (req, res) => {
    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");

    try {
        const code = req.query.code;

        if (!code) {
            return res.send(renderDashboard());
        }

        if (!CLOVER_CLIENT_ID || !CLOVER_CLIENT_SECRET) {
            return res.status(500).send(`
                <h1>Missing Clover environment variables</h1>
                <p>Please add CLOVER_CLIENT_ID and CLOVER_CLIENT_SECRET inside Render.</p>
                <a href="/">Back to InventoryRite</a>
            `);
        }

        console.log("Clover OAuth code received.");

        const tokenResponse = await cloverApi.post(
            `${CLOVER_API_BASE_URL}/oauth/token`,
            new URLSearchParams({
                client_id: CLOVER_CLIENT_ID,
                client_secret: CLOVER_CLIENT_SECRET,
                code: code
            }).toString(),
            {
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded"
                }
            }
        );

        const tokenData = tokenResponse.data;

        await saveCloverConnection({
            merchant_id: req.query.merchant_id || req.query.merchantId || tokenData.merchant_id || "",
            employee_id: req.query.employee_id || req.query.employeeId || tokenData.employee_id || "",
            access_token: tokenData.access_token || "",
            connected_at: new Date().toISOString()
        });

        console.log("Clover connected successfully.");
        console.log({
            merchant_id: latestCloverConnection.merchant_id,
            employee_id: latestCloverConnection.employee_id,
            hasAccessToken: !!latestCloverConnection.access_token
        });

        return res.send(renderDashboard(latestCloverConnection));
    } catch (error) {
        console.error("Clover Root OAuth Error:", error.response?.data || error.message);

        return res.status(500).send(`
            <h1>Clover OAuth failed</h1>
            <pre>${safe(JSON.stringify(error.response?.data || error.message, null, 2))}</pre>
            <a href="/">Back to InventoryRite</a>
        `);
    }
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
        databaseEnabled: USE_DATABASE,
        latestConnection: {
            connected: latestCloverConnection.connected,
            merchant_id: latestCloverConnection.merchant_id,
            employee_id: latestCloverConnection.employee_id,
            connected_at: latestCloverConnection.connected_at,
            hasAccessToken: !!latestCloverConnection.access_token
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

    const cloverAuthUrl =
        `${CLOVER_BASE_URL}/oauth/authorize` +
        `?client_id=${encodeURIComponent(CLOVER_CLIENT_ID)}` +
        `&response_type=code` +
        `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}`;

    console.log("Redirecting to Clover OAuth...");
    return res.redirect(cloverAuthUrl);
});

/*
|--------------------------------------------------------------------------
| CLOVER CONNECTION STATUS ROUTE
|--------------------------------------------------------------------------
*/

app.get("/clover-connection", (req, res) => {
    res.json({
        success: true,
        connection: {
            connected: latestCloverConnection.connected,
            merchant_id: latestCloverConnection.merchant_id,
            employee_id: latestCloverConnection.employee_id,
            connected_at: latestCloverConnection.connected_at,
            hasAccessToken: !!latestCloverConnection.access_token
        }
    });
});

/*
|--------------------------------------------------------------------------
| CLOVER MERCHANT INFO ROUTE
|--------------------------------------------------------------------------
*/

app.get("/clover-merchant", async (req, res) => {
    try {
        const { accessToken, merchantId } = getConnectionFromRequest(req);

        if (!accessToken || !merchantId) {
            return res.status(400).json({
                success: false,
                message: "Missing token or merchantId."
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
        const { accessToken, merchantId } = getConnectionFromRequest(req);

        if (!accessToken || !merchantId) {
            return res.status(400).json({
                success: false,
                message: "Missing token or merchantId."
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
        const { accessToken, merchantId } = getConnectionFromRequest(req);

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
        const { accessToken, merchantId } = getConnectionFromRequest(req);
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
        const { accessToken, merchantId } = getConnectionFromRequest(req);
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
        const { accessToken, merchantId } = getConnectionFromRequest(req);

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
        const { merchantId } = getConnectionFromRequest(req);

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

app.post("/item-cost/:itemId", async (req, res) => {
    try {
        const { accessToken, merchantId } = getConnectionFromRequest(req);
        const itemId = req.params.itemId;
        const costCents = Number(req.body.costCents || 0);

        if (!merchantId || !itemId) {
            return res.status(400).json({
                success: false,
                message: "Missing merchantId or itemId."
            });
        }

        if (!isValidMoneyCents(costCents)) {
            return res.status(400).json({
                success: false,
                message: "Invalid cost amount."
            });
        }

        const savedCostCents = await saveItemCostForMerchant(merchantId, itemId, costCents);
        let cloverCostSynced = false;
        let cloverCostSyncError = null;

        if (accessToken) {
            try {
                await cloverApi.post(
                    `${CLOVER_API_BASE_URL}/v3/merchants/${merchantId}/items/${itemId}`,
                    { cost: savedCostCents },
                    { headers: cloverHeaders(accessToken) }
                );
                cloverCostSynced = true;
            } catch (cloverError) {
                cloverCostSynced = false;
                cloverCostSyncError = cloverError.response?.data || cloverError.message || "Clover cost sync failed.";
                console.warn("Clover cost sync warning:", cloverCostSyncError);
            }
        }

        res.json({
            success: true,
            message: cloverCostSynced
                ? "Item cost saved and synced to Clover."
                : "Item cost saved in InventoryRite. Clover cost sync was not confirmed.",
            databaseEnabled: USE_DATABASE,
            itemId,
            costCents: savedCostCents,
            cloverCostSynced,
            cloverCostSyncError
        });
    } catch (error) {
        console.error("Save Item Cost Error:", error.message);
        res.status(500).json({
            success: false,
            message: "Failed to save item cost.",
            error: error.message
        });
    }
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
    </style>
</head>
<body>
    <div class="wrap">
        <p><a href="/">← Back to Inventory</a></p>
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