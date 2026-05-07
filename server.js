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

        .wrap { max-width: 1180px; margin: 26px auto; padding: 0 22px 50px; }

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
            overflow: auto;
            background: white;
        }

        table { width: 100%; border-collapse: collapse; min-width: 1060px; }
        th, td { padding: 13px 14px; border-bottom: 1px solid var(--line); text-align: left; font-size: 13px; vertical-align: middle; }
        th { background: #f8fafc; color: #334155; font-weight: 900; }
        tr:last-child td { border-bottom: 0; }
        td.muted { color: var(--muted); }

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

        @media (max-width: 980px) {
            .hero, .stats-row, .add-grid { grid-template-columns: 1fr; }
            .hero { flex-direction: column; }
            .hero h2 { font-size: 28px; }
            .topbar { align-items: flex-start; gap: 14px; flex-direction: column; }
            .table-top { flex-direction: column; }
            .toolbar { width: 100%; justify-content: flex-start; }
            .search-input { width: 100%; min-width: 100%; max-width: 100%; }
            .bulk-controls { flex-direction: column; align-items: flex-start; }
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

            <div class="table-wrap">
                <table>
                    <thead>
                        <tr>
                            <th class="col-check">
                                <input type="checkbox" id="selectAllCheckbox" title="Select all visible" />
                            </th>
                            <th>Product Name</th>
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
                            <td colspan="10" class="empty">
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
        var bulkUpdatedItemIds = [];
        var isBusy = false;
        var pendingConfirmAction = null;

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

        function setButtonsDisabled(disabled) {
            var buttons = document.querySelectorAll("button");
            buttons.forEach(function (btn) {
                if (btn.id === "confirmCancel" || btn.id === "confirmYes") return;
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
            }).sort(function (a, b) {
                return String(a.name || "").localeCompare(String(b.name || ""));
            });

            updateStats(items || []);

            if (!items || !items.length) {
                body.innerHTML =
                    '<tr><td colspan="10" class="empty">' +
                    '<strong>No Clover products found.</strong>' +
                    'Click Add Product to create your first item.' +
                    '</td></tr>';
                syncBulkUI();
                return;
            }

            if (!filtered.length) {
                body.innerHTML =
                    '<tr><td colspan="10" class="empty">' +
                    '<strong>No matching products found.</strong>' +
                    'Try a different product name, SKU, or Clover ID.' +
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
                var priceDollars = (Number(item.price || 0) / 100).toFixed(2);
                var isSelected = selectedItemIds.has(itemId);
                var isBulkUpdated = bulkUpdatedItemIds.indexOf(itemId) >= 0;

                row.setAttribute("data-row-id", itemId);

                if (lastUpdatedItemId && itemId === lastUpdatedItemId) {
                    row.className = "row-updated";
                } else if (isBulkUpdated) {
                    row.className = "row-bulk-updated";
                }

                if (isSelected) {
                    row.classList.add("row-selected");
                }

                row.innerHTML =
                    "<td class='col-check'><input type='checkbox' data-item-id='" + escapeHtml(itemId) + "' " + (isSelected ? "checked" : "") + " /></td>" +
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

            syncBulkUI();
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

        async function loadItems() {
            if (isBusy) return;

            try {
                var connection = requireConnection();
                if (!connection) return;

                startBusy();

                var data = await fetchJson(
                    "/clover-items?token=" + encodeURIComponent(connection.token) +
                    "&merchantId=" + encodeURIComponent(connection.merchantId)
                );

                loadedItems = data.data && data.data.elements ? data.data.elements : [];
                renderItems(loadedItems);
                showToast("Inventory loaded: " + loadedItems.length + " product(s).", "success");
            } catch (error) {
                showToast(error && error.message ? error.message : "Unable to load inventory.", "error");
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

        bind("confirmCancel", "click", closeConfirm);
        bind("confirmYes", "click", function () {
            var action = pendingConfirmAction;
            closeConfirm();
            if (typeof action === "function") action();
        });

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
/clover-delete-item/:itemId</pre>
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