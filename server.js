const express = require("express");
const cors = require("cors");
const axios = require("axios");
require("dotenv").config();

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

const cloverApi = axios.create({
    timeout: REQUEST_TIMEOUT_MS
});

/*
|--------------------------------------------------------------------------
| SIMPLE IN-MEMORY SESSION STORAGE
|--------------------------------------------------------------------------
| Sandbox/testing only. Render restarts clear this.
| For production, replace this with PostgreSQL/Supabase token storage.
|--------------------------------------------------------------------------
*/

let latestCloverConnection = {
    connected: false,
    merchant_id: "",
    employee_id: "",
    access_token: "",
    connected_at: ""
};

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
    <title>InventoryRite Clover Connector</title>
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

        body {
            margin: 0;
            font-family: Arial, Helvetica, sans-serif;
            background:
                radial-gradient(circle at top left, rgba(22, 163, 74, 0.12), transparent 32%),
                radial-gradient(circle at top right, rgba(37, 99, 235, 0.08), transparent 30%),
                linear-gradient(180deg, #f8fafc 0%, #eef2f7 100%);
            color: var(--text);
        }

        .topbar {
            background: rgba(255,255,255,0.92);
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

        .wrap { max-width: 1240px; margin: 28px auto; padding: 0 22px 50px; }

        .hero {
            display: grid;
            grid-template-columns: 1.35fr 0.85fr;
            gap: 22px;
            align-items: stretch;
            margin-bottom: 22px;
        }

        .card {
            background: rgba(255,255,255,0.96);
            border: 1px solid var(--line);
            border-radius: var(--radius);
            box-shadow: var(--shadow);
        }

        .hero-main {
            padding: 34px;
            overflow: hidden;
            position: relative;
        }

        .hero-main:after {
            content: "";
            position: absolute;
            width: 280px;
            height: 280px;
            border-radius: 50%;
            right: -90px;
            top: -105px;
            background: rgba(34, 197, 94, 0.13);
            pointer-events: none;
        }

        .eyebrow {
            color: var(--green);
            font-weight: 900;
            letter-spacing: .08em;
            text-transform: uppercase;
            font-size: 12px;
            margin-bottom: 10px;
        }

        .hero h2 {
            margin: 0;
            font-size: 35px;
            line-height: 1.08;
            letter-spacing: -0.035em;
            max-width: 760px;
        }

        .hero-text {
            margin: 15px 0 0;
            color: var(--muted);
            line-height: 1.6;
            max-width: 760px;
            font-size: 15px;
        }

        .actions { display: flex; flex-wrap: wrap; gap: 12px; margin-top: 24px; position: relative; z-index: 3; }

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
            min-height: 44px;
            transition: transform .12s ease, box-shadow .12s ease, opacity .12s ease;
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
        .btn-small { min-height: 34px; padding: 8px 11px; font-size: 12px; border-radius: 10px; }

        .status-card { padding: 24px; }

        .status-row {
            display: flex;
            justify-content: space-between;
            gap: 14px;
            border-bottom: 1px solid var(--line);
            padding: 13px 0;
        }

        .status-row:last-child { border-bottom: 0; }
        .status-label { color: var(--muted); font-size: 13px; }
        .status-value { font-weight: 900; font-size: 13px; text-align: right; word-break: break-all; }

        .grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 18px;
            margin-bottom: 22px;
        }

        .mini-card { padding: 20px; }
        .mini-card h3 { margin: 0 0 8px; font-size: 17px; }
        .mini-card p { margin: 0; color: var(--muted); line-height: 1.5; font-size: 14px; }

        .workbench {
            display: grid;
            grid-template-columns: 0.9fr 1.1fr;
            gap: 22px;
            margin-bottom: 22px;
        }

        .panel { padding: 24px; }
        .panel h3 { margin: 0 0 8px; font-size: 21px; }
        .panel-desc { margin: 0 0 18px; color: var(--muted); line-height: 1.5; font-size: 14px; }

        label { display: block; font-size: 13px; font-weight: 900; margin-bottom: 7px; }

        input {
            width: 100%;
            border: 1px solid #d1d5db;
            border-radius: 13px;
            padding: 13px 14px;
            font-size: 14px;
            outline: none;
            margin-bottom: 14px;
            background: white;
        }

        input:focus {
            border-color: var(--green);
            box-shadow: 0 0 0 3px rgba(34, 197, 94, 0.15);
        }

        .form-row {
            display: grid;
            grid-template-columns: 1fr 0.45fr;
            gap: 12px;
        }

        .button-row { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }

        .result {
            background: #0f172a;
            color: #e5e7eb;
            border-radius: 15px;
            padding: 18px;
            min-height: 280px;
            overflow: auto;
            white-space: pre-wrap;
            font-family: Consolas, Monaco, monospace;
            font-size: 13px;
            line-height: 1.5;
        }

        .note {
            background: #fffbeb;
            color: #92400e;
            border: 1px solid #fde68a;
            padding: 13px 14px;
            border-radius: 13px;
            font-size: 13px;
            line-height: 1.45;
            margin-top: 14px;
            position: relative;
            z-index: 3;
        }

        .inventory-card { padding: 24px; }

        .table-top {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            gap: 14px;
            margin-bottom: 16px;
        }

        .table-top h3 { margin: 0 0 6px; font-size: 22px; }
        .table-top p { margin: 0; color: var(--muted); font-size: 14px; line-height: 1.5; }

        .toolbar {
            display: flex;
            gap: 10px;
            align-items: center;
            flex-wrap: wrap;
        }

        .search-input {
            min-width: 260px;
            margin-bottom: 0;
            padding: 12px 14px;
        }

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
            overflow: auto;
            background: white;
        }

        table { width: 100%; border-collapse: collapse; min-width: 1020px; }
        th, td { padding: 13px 14px; border-bottom: 1px solid var(--line); text-align: left; font-size: 13px; vertical-align: middle; }
        th { background: #f8fafc; color: #334155; font-weight: 900; }
        tr:last-child td { border-bottom: 0; }
        td.muted { color: var(--muted); }

        tr.row-updated {
            animation: rowFlash 1.4s ease;
        }

        @keyframes rowFlash {
            0% { background: #dcfce7; }
            100% { background: white; }
        }

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
            min-width: 95px;
            max-width: 115px;
            padding: 9px 10px;
            margin: 0;
            border-radius: 10px;
        }

        .name-input {
            min-width: 190px;
            padding: 9px 10px;
            margin: 0;
            border-radius: 10px;
        }

        .row-actions {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
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

        .modal-backdrop.show {
            display: flex;
        }

        .modal {
            width: 100%;
            max-width: 460px;
            background: white;
            border-radius: 20px;
            box-shadow: 0 24px 80px rgba(15, 23, 42, 0.28);
            border: 1px solid var(--line);
            padding: 24px;
        }

        .modal h3 {
            margin: 0 0 8px;
            font-size: 21px;
        }

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

        @media (max-width: 980px) {
            .hero, .workbench, .grid, .stats-row { grid-template-columns: 1fr; }
            .hero h2 { font-size: 28px; }
            .topbar { align-items: flex-start; gap: 14px; flex-direction: column; }
            .button-row { grid-template-columns: 1fr; }
            .table-top { flex-direction: column; }
            .toolbar { width: 100%; }
            .search-input { width: 100%; min-width: 100%; }
        }
    </style>
</head>
<body>

    <div class="topbar">
        <div class="brand">
            <div class="logo">IR</div>
            <div>
                <h1>InventoryRite Clover Connector</h1>
                <p>Inventory bridge for Clover merchants</p>
            </div>
        </div>

        <div class="badge ${connected ? "connected" : "disconnected"}" id="topBadge">
            ${connected ? "Connected to Clover" : "Not Connected"}
        </div>
    </div>

    <main class="wrap">

        <section class="hero">
            <div class="card hero-main">
                <div class="eyebrow">Clover Inventory App</div>
                <h2>Manage Clover inventory through your InventoryRite connector.</h2>
                <p class="hero-text">
                    This dashboard confirms that your Clover merchant connection works, reads Clover inventory,
                    creates test items, edits items, deletes test items, and gives you a clean starting point for a real Clover App Market product.
                </p>

                <div class="actions">
                    <a class="btn btn-primary" href="/connect-clover">Connect Clover</a>
                    <button id="btnLoadTop" type="button" class="btn btn-secondary">Load Clover Items</button>
                    <button id="btnCreateTop" type="button" class="btn btn-dark">Create Test Item</button>
                    <button id="btnHealthTop" type="button" class="btn btn-light">Check Backend</button>
                </div>

                <div class="note">
                    Connect Clover to load and manage products. Advanced token entry is kept available for setup and support testing.
                </div>
            </div>

            <div class="card status-card">
                <div class="status-row">
                    <div class="status-label">Connection</div>
                    <div class="status-value" id="connectionDisplay">${connected ? "Connected" : "Not connected"}</div>
                </div>
                <div class="status-row">
                    <div class="status-label">Merchant ID</div>
                    <div class="status-value" id="merchantDisplay">${safe(merchantId) || "Not detected"}</div>
                </div>
                <div class="status-row">
                    <div class="status-label">Employee ID</div>
                    <div class="status-value" id="employeeDisplay">${safe(employeeId) || "Not detected"}</div>
                </div>
                <div class="status-row">
                    <div class="status-label">Token</div>
                    <div class="status-value" id="tokenDisplay">${formatTokenForDisplay(accessToken) || "Not saved"}</div>
                </div>
                <div class="status-row">
                    <div class="status-label">Backend</div>
                    <div class="status-value">Render Live</div>
                </div>
                <div class="status-row">
                    <div class="status-label">Mode</div>
                    ${IS_PRODUCTION_CLOVER ? `<div class="status-value">Production</div>` : `<div class="status-value">Sandbox</div>`}
                </div>
                <div class="status-row">
                    <div class="status-label">Connected At</div>
                    <div class="status-value" id="connectedAtDisplay">${safe(connectedAt) || "Not connected"}</div>
                </div>
            </div>
        </section>

        <section class="grid">
            <div class="card mini-card">
                <h3>Read Items</h3>
                <p>Pull inventory from Clover and display it in a clean merchant-facing table.</p>
            </div>
            <div class="card mini-card">
                <h3>Create Items</h3>
                <p>Create Clover inventory items directly through your Render backend.</p>
            </div>
            <div class="card mini-card">
                <h3>Edit + Delete</h3>
                <p>Update names/prices and remove test items when needed.</p>
            </div>
            <div class="card mini-card">
                <h3>Product Export</h3>
                <p>Ready for product export and future inventory workflows.</p>
            </div>
        </section>

        <section class="workbench">
            <div class="card panel">
                <h3>Connection Test</h3>
                <p class="panel-desc">
                    Use the OAuth connection or paste your Merchant API token manually.
                </p>

                <label for="token">Merchant API Token</label>
                <input id="token" type="password" value="${safe(accessToken)}" placeholder="Paste Clover Merchant API token here" />

                <label for="merchantId">Merchant ID</label>
                <input id="merchantId" type="text" value="${safe(merchantId)}" placeholder="Example: 7E2G3TE77A091" />

                <div class="form-row">
                    <div>
                        <label for="itemName">Item Name</label>
                        <input id="itemName" type="text" value="InvoiceRite Test Item" />
                    </div>
                    <div>
                        <label for="itemPrice">Price Cents</label>
                        <input id="itemPrice" type="number" value="199" />
                    </div>
                </div>

                <div class="button-row">
                    <button id="btnMerchant" type="button" class="btn btn-secondary">Test Merchant</button>
                    <button id="btnLoadPanel" type="button" class="btn btn-secondary">Load Items</button>
                </div>

                <button id="btnCreatePanel" type="button" class="btn btn-primary" style="width:100%; margin-top:10px;">Create Clover Item</button>
            </div>

            <div class="card panel">
                <h3>Activity Status</h3>
                <p class="panel-desc">
                    Use this panel to confirm connection, inventory loading, and product updates.
                </p>

                <div style="background:#ecfdf5; border:1px solid #bbf7d0; border-radius:16px; padding:18px; color:#166534; font-weight:900; margin-bottom:14px;">
                    Ready to manage Clover inventory.
                </div>

                <div style="background:#f8fafc; border:1px solid #e5e7eb; border-radius:16px; padding:16px; color:#334155; font-size:14px; line-height:1.6;">
                    <strong>Merchant tools included:</strong><br>
                    Load products, create test items, edit item names, edit prices, delete items, search inventory, and preview product data.
                </div>

                <details style="margin-top:14px;">
                    <summary style="cursor:pointer; font-weight:900; color:#2563eb;">Advanced developer log</summary>
                    <pre class="result" id="result" style="margin-top:12px; min-height:180px;">Ready. Connect Clover, or paste your merchant token and click a button.</pre>
                </details>
            </div>
        </section>

        <section class="card inventory-card">
            <div class="table-top">
                <div>
                    <h3>Clover Inventory</h3>
                    <p>Search, edit, refresh, and delete Clover items from one clean table.</p>
                </div>
                <div class="toolbar">
                    <input id="inventorySearch" class="search-input" type="text" placeholder="Search item, SKU, or Clover ID..." />
                    <button id="btnRefreshInventory" type="button" class="btn btn-secondary">Refresh Inventory</button>
                    <button id="btnSyncPreview" type="button" class="btn btn-light">Sync Preview</button>
                </div>
            </div>

            <div class="stats-row">
                <div class="stat-box">
                    <div class="stat-label">Loaded Items</div>
                    <div class="stat-value" id="statLoaded">0</div>
                </div>
                <div class="stat-box">
                    <div class="stat-label">Visible Items</div>
                    <div class="stat-value" id="statVisible">0</div>
                </div>
                <div class="stat-box">
                    <div class="stat-label">Available Items</div>
                    <div class="stat-value" id="statAvailable">0</div>
                </div>
                <div class="stat-box">
                    <div class="stat-label">Total Menu Value</div>
                    <div class="stat-value" id="statValue">$0.00</div>
                </div>
            </div>

            <div class="table-wrap">
                <table>
                    <thead>
                        <tr>
                            <th>Item Name</th>
                            <th>Price</th>
                            <th>SKU / Code</th>
                            <th>Available</th>
                            <th>Hidden</th>
                            <th>Revenue</th>
                            <th>Modified</th>
                            <th>Clover ID</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody id="itemsBody">
                        <tr>
                            <td colspan="9" class="empty">
                                <strong>No Clover inventory loaded yet.</strong>
                                Click “Load Clover Items” to pull inventory from your merchant.
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </section>

        <div class="footer">
            InventoryRite Clover Connector · Process Rite Inc
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

    <script>
    (function () {
        var embeddedConnection = {
            connected: ${connected ? "true" : "false"},
            merchant_id: ${JSON.stringify(merchantId)},
            employee_id: ${JSON.stringify(employeeId)},
            access_token: ${JSON.stringify(accessToken)},
            connected_at: ${JSON.stringify(connectedAt)}
        };

        var loadedItems = [];
        var lastUpdatedItemId = "";
        var isBusy = false;
        var pendingConfirmAction = null;

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
            var tokenBox = byId("token");
            return (tokenBox && tokenBox.value ? tokenBox.value.trim() : "") || embeddedConnection.access_token || "";
        }

        function getMerchantId() {
            var merchantBox = byId("merchantId");
            return (merchantBox && merchantBox.value ? merchantBox.value.trim() : "") || embeddedConnection.merchant_id || "";
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

        function setBusyMessage(text) {
            var result = byId("result");
            if (result) result.textContent = text || "Loading...";
        }

        function showResult(data) {
            var result = byId("result");
            if (result) result.textContent = JSON.stringify(data, null, 2);
        }

        function showError(error) {
            var message = error && error.message ? error.message : String(error || "Request failed.");
            var result = byId("result");
            if (result) result.textContent = "ERROR:\\n" + message;
            showToast(message, "error");
        }

        function setButtonsDisabled(disabled) {
            var buttons = document.querySelectorAll("button");
            buttons.forEach(function (btn) {
                if (btn.id === "confirmCancel" || btn.id === "confirmYes") return;
                btn.disabled = disabled;
            });
        }

        function startBusy(message) {
            isBusy = true;
            setButtonsDisabled(true);
            setBusyMessage(message || "Working...");
        }

        function stopBusy() {
            isBusy = false;
            setButtonsDisabled(false);
        }

        function requireConnection() {
            var token = getToken();
            var merchantId = getMerchantId();

            if (!token || !merchantId) {
                showToast("Please connect Clover or enter both token and merchant ID.", "error");
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

        function updateStats(items) {
            items = items || [];
            var loaded = items.length;
            var visible = items.filter(function (item) { return !item.hidden; }).length;
            var available = items.filter(function (item) { return item.available !== false; }).length;
            var totalCents = items.reduce(function (sum, item) {
                return sum + Number(item.price || 0);
            }, 0);

            var statLoaded = byId("statLoaded");
            var statVisible = byId("statVisible");
            var statAvailable = byId("statAvailable");
            var statValue = byId("statValue");

            if (statLoaded) statLoaded.textContent = String(loaded);
            if (statVisible) statVisible.textContent = String(visible);
            if (statAvailable) statAvailable.textContent = String(available);
            if (statValue) statValue.textContent = formatCurrencyFromCents(totalCents);
        }

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
            }).sort(function (a, b) {
                return String(a.name || "").localeCompare(String(b.name || ""));
            });

            updateStats(items || []);

            if (!items || !items.length) {
                body.innerHTML =
                    '<tr><td colspan="9" class="empty">' +
                    '<strong>No Clover inventory found.</strong>' +
                    'Create your first item using the form above, then refresh inventory.' +
                    '</td></tr>';
                return;
            }

            if (!filtered.length) {
                body.innerHTML =
                    '<tr><td colspan="9" class="empty">' +
                    '<strong>No matching items found.</strong>' +
                    'Try a different item name, SKU, or Clover ID.' +
                    '</td></tr>';
                return;
            }

            filtered.forEach(function (item) {
                var row = document.createElement("tr");
                var sku = item.sku || item.code || item.productCode || "—";
                var available = item.available === false ? '<span class="pill warn">No</span>' : '<span class="pill good">Yes</span>';
                var hidden = item.hidden ? '<span class="pill warn">Hidden</span>' : '<span class="pill good">Visible</span>';
                var revenue = item.isRevenue === false ? '<span class="pill warn">No</span>' : '<span class="pill good">Yes</span>';
                var itemId = item.id || "";
                var itemName = item.name || "Unnamed Item";
                var priceDollars = (Number(item.price || 0) / 100).toFixed(2);

                if (lastUpdatedItemId && itemId === lastUpdatedItemId) {
                    row.className = "row-updated";
                }

                row.innerHTML =
                    "<td><input class='name-input' data-name-for='" + escapeHtml(itemId) + "' value='" + escapeHtml(itemName) + "' /></td>" +
                    "<td><input class='small-input' data-price-for='" + escapeHtml(itemId) + "' value='" + escapeHtml(priceDollars) + "' /></td>" +
                    "<td class='muted'>" + escapeHtml(sku) + "</td>" +
                    "<td>" + available + "</td>" +
                    "<td>" + hidden + "</td>" +
                    "<td>" + revenue + "</td>" +
                    "<td class='muted'>" + formatDateFromClover(item.modifiedTime) + "</td>" +
                    "<td class='muted'>" + escapeHtml(itemId || "—") + "</td>" +
                    "<td><div class='row-actions'>" +
                        "<button type='button' class='btn btn-secondary btn-small' data-action='save' data-id='" + escapeHtml(itemId) + "'>Save</button>" +
                        "<button type='button' class='btn btn-danger btn-small' data-action='delete' data-id='" + escapeHtml(itemId) + "' data-name='" + escapeHtml(itemName) + "'>Delete</button>" +
                    "</div></td>";

                body.appendChild(row);
            });

            if (lastUpdatedItemId) {
                setTimeout(function () {
                    lastUpdatedItemId = "";
                    renderItems(loadedItems);
                }, 1400);
            }
        }

        async function fetchJson(url, options) {
            var response = await fetch(url, options || {});
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

        async function checkHealth() {
            if (isBusy) return;

            try {
                startBusy("Checking backend health...");
                var data = await fetchJson("/health");
                showResult(data);
                showToast("Backend is live.", "success");
            } catch (error) {
                showError(error);
            } finally {
                stopBusy();
            }
        }

        async function loadMerchant() {
            if (isBusy) return;

            try {
                var connection = requireConnection();
                if (!connection) return;

                startBusy("Loading merchant info...");

                var data = await fetchJson(
                    "/clover-merchant?token=" + encodeURIComponent(connection.token) +
                    "&merchantId=" + encodeURIComponent(connection.merchantId)
                );

                showResult(data);

                var merchantDisplay = byId("merchantDisplay");
                if (merchantDisplay) merchantDisplay.textContent = connection.merchantId;

                showToast("Merchant info loaded successfully.", "success");
            } catch (error) {
                showError(error);
            } finally {
                stopBusy();
            }
        }

        async function loadItems() {
            if (isBusy) return;

            try {
                var connection = requireConnection();
                if (!connection) return;

                startBusy("Loading Clover inventory items...");

                var data = await fetchJson(
                    "/clover-items?token=" + encodeURIComponent(connection.token) +
                    "&merchantId=" + encodeURIComponent(connection.merchantId)
                );

                showResult(data);
                loadedItems = data.data && data.data.elements ? data.data.elements : [];
                renderItems(loadedItems);
                showToast("Clover inventory loaded: " + loadedItems.length + " item(s).", "success");
            } catch (error) {
                showError(error);
            } finally {
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

                var name = nameBox && nameBox.value ? nameBox.value.trim() : "InvoiceRite Test Item";
                var price = priceBox && priceBox.value ? priceBox.value.trim() : "199";

                if (!name) {
                    showToast("Item name cannot be empty.", "error");
                    return;
                }

                if (Number.isNaN(Number(price)) || Number(price) < 0) {
                    showToast("Price cents must be a valid positive number.", "error");
                    return;
                }

                startBusy("Creating Clover item...");

                var data = await fetchJson(
                    "/clover-create-item?token=" + encodeURIComponent(connection.token) +
                    "&merchantId=" + encodeURIComponent(connection.merchantId),
                    {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ name: name, price: Number(price) })
                    }
                );

                showResult(data);
                lastUpdatedItemId = data && data.data && data.data.id ? data.data.id : "";
                showToast("Clover item created successfully.", "success");

                stopBusy();
                await loadItems();
            } catch (error) {
                showError(error);
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
                    showToast("Item name cannot be empty.", "error");
                    return;
                }

                if (priceCents === null) {
                    showToast("Price must be a valid dollar amount.", "error");
                    return;
                }

                startBusy("Updating Clover item...");

                var data = await fetchJson(
                    "/clover-update-item/" + encodeURIComponent(itemId) +
                    "?token=" + encodeURIComponent(connection.token) +
                    "&merchantId=" + encodeURIComponent(connection.merchantId),
                    {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ name: name, price: priceCents })
                    }
                );

                showResult(data);
                lastUpdatedItemId = itemId;
                showToast("Clover item updated.", "success");

                stopBusy();
                await loadItems();
            } catch (error) {
                showError(error);
                stopBusy();
            }
        }

        async function deleteItem(itemId) {
            if (isBusy) return;

            try {
                var connection = requireConnection();
                if (!connection) return;

                startBusy("Deleting Clover item...");

                var data = await fetchJson(
                    "/clover-delete-item/" + encodeURIComponent(itemId) +
                    "?token=" + encodeURIComponent(connection.token) +
                    "&merchantId=" + encodeURIComponent(connection.merchantId),
                    { method: "POST" }
                );

                showResult(data);
                showToast("Clover item deleted.", "success");

                stopBusy();
                await loadItems();
            } catch (error) {
                showError(error);
                stopBusy();
            }
        }

        function prepareSyncPreview() {
            if (isBusy) return;

            if (!loadedItems || !loadedItems.length) {
                showToast("Load Clover inventory first.", "error");
                return;
            }

            var preview = loadedItems.map(function (item) {
                return {
                    cloverId: item.id || "",
                    productName: item.name || "",
                    sku: item.sku || item.code || item.productCode || "",
                    sellingPrice: Number(item.price || 0) / 100,
                    available: item.available !== false,
                    hidden: !!item.hidden
                };
            });

            showResult({
                success: true,
                message: "Sync preview ready for product export or future inventory workflows.",
                count: preview.length,
                items: preview
            });

            showToast("Sync preview created.", "success");
        }

        bind("btnLoadTop", "click", loadItems);
        bind("btnCreateTop", "click", createItem);
        bind("btnHealthTop", "click", checkHealth);
        bind("btnMerchant", "click", loadMerchant);
        bind("btnLoadPanel", "click", loadItems);
        bind("btnCreatePanel", "click", createItem);
        bind("btnRefreshInventory", "click", loadItems);
        bind("btnSyncPreview", "click", prepareSyncPreview);
        bind("inventorySearch", "input", function () { renderItems(loadedItems); });

        bind("confirmCancel", "click", closeConfirm);
        bind("confirmYes", "click", function () {
            var action = pendingConfirmAction;
            closeConfirm();
            if (typeof action === "function") action();
        });

        var modal = byId("confirmModal");
        if (modal) {
            modal.addEventListener("click", function (event) {
                if (event.target === modal) closeConfirm();
            });
        }

        var itemsBody = byId("itemsBody");
        if (itemsBody) {
            itemsBody.addEventListener("click", function (event) {
                var target = event.target;
                if (!target || !target.getAttribute) return;

                var action = target.getAttribute("data-action");
                var itemId = target.getAttribute("data-id");
                var itemName = target.getAttribute("data-name") || "this item";

                if (action === "save") {
                    updateItem(itemId);
                }

                if (action === "delete") {
                    openConfirm(
                        "Delete Clover Item?",
                        "This will delete " + itemName + " from the Clover merchant. This cannot be undone.",
                        function () { deleteItem(itemId); }
                    );
                }
            });
        }

        if (embeddedConnection.connected && embeddedConnection.access_token && embeddedConnection.merchant_id) {
            showToast("Clover OAuth connection saved for this sandbox session.", "success");
        }

        updateStats([]);
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

        latestCloverConnection = {
            connected: true,
            merchant_id: req.query.merchant_id || req.query.merchantId || tokenData.merchant_id || "",
            employee_id: req.query.employee_id || req.query.employeeId || tokenData.employee_id || "",
            access_token: tokenData.access_token || "",
            connected_at: new Date().toISOString()
        };

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

        const itemName = String(req.body.name || "InvoiceRite Test Item").trim();
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
| CLOVER CREATE TEST ITEM ROUTE - GET
| Kept for backwards compatibility with older button/link tests.
|--------------------------------------------------------------------------
*/

app.get("/clover-create-test-item", async (req, res) => {
    try {
        const { accessToken, merchantId } = getConnectionFromRequest(req);

        if (!accessToken || !merchantId) {
            return res.status(400).json({
                success: false,
                message: "Missing token or merchantId."
            });
        }

        const itemName = String(req.query.name || "InvoiceRite Test Item").trim();
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
            message: "Clover test item created successfully",
            data: createResponse.data
        });
    } catch (error) {
        console.error("Clover Create Test Item Error:", error.response?.data || error.message);

        const cloverError = getCloverError(error);
        res.status(cloverError.status).json({
            success: false,
            message: "Failed to create Clover test item",
            error: cloverError.data
        });
    }
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
        connectedAt: latestCloverConnection.connected_at || null
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

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
