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

const REDIRECT_URI = "https://inventoryrite-api.onrender.com/";
const CLOVER_BASE_URL = "https://sandbox.dev.clover.com";
const CLOVER_API_BASE_URL = "https://apisandbox.dev.clover.com";

/*
|--------------------------------------------------------------------------
| SIMPLE IN-MEMORY SESSION STORAGE
|--------------------------------------------------------------------------
| Sandbox/testing only. Render restarts clear this.
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
            --blue: #2563eb;
            --blue-soft: #eef2ff;
            --red: #b91c1c;
            --red-soft: #fee2e2;
            --amber: #b45309;
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

        .actions { display: flex; flex-wrap: wrap; gap: 12px; margin-top: 24px; position: relative; z-index: 2; }

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
        }

        .btn:hover { transform: translateY(-1px); }
        .btn:disabled { opacity: .58; cursor: not-allowed; transform: none; }

        .btn-primary { background: var(--green); color: white; box-shadow: 0 9px 20px rgba(21, 128, 61, 0.22); }
        .btn-primary:hover { background: var(--green-dark); }
        .btn-secondary { background: var(--blue-soft); color: #1d4ed8; }
        .btn-dark { background: #111827; color: white; }
        .btn-light { background: #f8fafc; color: #111827; border: 1px solid var(--line); }
        .btn-danger { background: var(--red-soft); color: var(--red); border: 1px solid #fecaca; }

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
            z-index: 2;
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
            padding: 22px;
            color: var(--muted);
            font-size: 14px;
            text-align: center;
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
            max-width: 360px;
            font-size: 14px;
            line-height: 1.45;
        }

        .toast.success { background: #166534; }
        .toast.error { background: #991b1b; }
        .toast.info { background: #1e3a8a; }

        .footer { color: var(--muted); text-align: center; margin-top: 30px; font-size: 13px; }

        @media (max-width: 980px) {
            .hero, .workbench, .grid { grid-template-columns: 1fr; }
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
                <div class="eyebrow">Clover Sandbox App</div>
                <h2>Manage Clover inventory through your InventoryRite connector.</h2>
                <p class="hero-text">
                    This dashboard confirms that your Clover merchant connection works, reads Clover inventory,
                    creates test items, edits items, deletes test items, and gives you a clean starting point for a real Clover App Market product.
                </p>

                <div class="actions">
                    <a class="btn btn-primary" href="/connect-clover">Connect Clover</a>
                    <button type="button" class="btn btn-secondary" onclick="loadItems()">Load Clover Items</button>
                    <button type="button" class="btn btn-dark" onclick="createItem()">Create Test Item</button>
                    <button type="button" class="btn btn-light" onclick="checkHealth()">Check Backend</button>
                </div>

                <div class="note">
                    Sandbox build: OAuth can auto-fill the merchant connection after Clover redirects back.
                    You can also paste a Merchant API token manually for testing.
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
                    <div class="status-value">Sandbox</div>
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
                <p>Create sandbox inventory items directly through your Render backend.</p>
            </div>
            <div class="card mini-card">
                <h3>Edit + Delete</h3>
                <p>Update names/prices and remove sandbox test items when needed.</p>
            </div>
            <div class="card mini-card">
                <h3>Sync Foundation</h3>
                <p>Ready to become Clover to InvoiceRite desktop sync.</p>
            </div>
        </section>

        <section class="workbench">
            <div class="card panel">
                <h3>Connection Test</h3>
                <p class="panel-desc">
                    Use the OAuth connection or paste your sandbox Merchant API token manually.
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
                    <button type="button" class="btn btn-secondary" onclick="loadMerchant()">Test Merchant</button>
                    <button type="button" class="btn btn-secondary" onclick="loadItems()">Load Items</button>
                </div>

                <button type="button" class="btn btn-primary" style="width:100%; margin-top:10px;" onclick="createItem()">Create Clover Item</button>
            </div>

            <div class="card panel">
                <h3>Live API Result</h3>
                <p class="panel-desc">
                    Results from your Render backend appear here.
                </p>
                <pre class="result" id="result">Ready. Connect Clover, or paste your merchant token and click a button.</pre>
            </div>
        </section>

        <section class="card inventory-card">
            <div class="table-top">
                <div>
                    <h3>Clover Inventory</h3>
                    <p>Search, edit, refresh, and delete sandbox Clover items from one clean table.</p>
                </div>
                <div class="toolbar">
                    <input id="inventorySearch" class="search-input" type="text" placeholder="Search item, SKU, or Clover ID..." oninput="applySearch()" />
                    <button type="button" class="btn btn-secondary" onclick="loadItems()">Refresh Inventory</button>
                    <button type="button" class="btn btn-light" onclick="prepareSyncPreview()">Sync Preview</button>
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
                            <td colspan="9" class="empty">No items loaded yet. Click “Load Clover Items”.</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </section>

        <div class="footer">
            InventoryRite Clover Connector · Sandbox Build · Process Rite Inc
        </div>

    </main>

    <div class="toast-wrap" id="toastWrap"></div>

    <script>
        var embeddedConnection = {
            connected: ${connected ? "true" : "false"},
            merchant_id: ${JSON.stringify(merchantId)},
            employee_id: ${JSON.stringify(employeeId)},
            access_token: ${JSON.stringify(accessToken)},
            connected_at: ${JSON.stringify(connectedAt)}
        };

        var loadedItems = [];

        function getToken() {
            var tokenBox = document.getElementById("token");
            return (tokenBox && tokenBox.value ? tokenBox.value.trim() : "") || embeddedConnection.access_token || "";
        }

        function getMerchantId() {
            var merchantBox = document.getElementById("merchantId");
            return (merchantBox && merchantBox.value ? merchantBox.value.trim() : "") || embeddedConnection.merchant_id || "";
        }

        function centsToDollars(cents) {
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
            var wrap = document.getElementById("toastWrap");
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

        function setBusy(text) {
            var result = document.getElementById("result");
            if (result) {
                result.textContent = text || "Loading...";
            }
        }

        function showResult(data) {
            var result = document.getElementById("result");
            if (result) {
                result.textContent = JSON.stringify(data, null, 2);
            }
        }

        function showError(error) {
            var message = error && error.message ? error.message : String(error || "Request failed.");
            var result = document.getElementById("result");
            if (result) {
                result.textContent = "ERROR:\\n" + message;
            }
            showToast(message, "error");
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

        function updateStatusFromData() {
            var merchantId = getMerchantId();
            var merchantDisplay = document.getElementById("merchantDisplay");
            if (merchantId && merchantDisplay) {
                merchantDisplay.textContent = merchantId;
            }
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

        function applySearch() {
            renderItems(loadedItems);
        }

        function renderItems(items) {
            var body = document.getElementById("itemsBody");
            if (!body) return;

            body.innerHTML = "";

            var searchBox = document.getElementById("inventorySearch");
            var search = searchBox && searchBox.value ? searchBox.value.trim().toLowerCase() : "";

            var filtered = (items || []).filter(function (item) {
                if (!search) return true;

                var sku = item.sku || item.code || item.productCode || "";
                var haystack = [
                    item.name || "",
                    sku,
                    item.id || ""
                ].join(" ").toLowerCase();

                return haystack.indexOf(search) >= 0;
            });

            if (!filtered.length) {
                body.innerHTML = '<tr><td colspan="9" class="empty">No Clover items found.</td></tr>';
                return;
            }

            filtered.forEach(function (item) {
                var row = document.createElement("tr");
                var sku = item.sku || item.code || item.productCode || "—";

                var available = item.available === false
                    ? '<span class="pill warn">No</span>'
                    : '<span class="pill good">Yes</span>';

                var hidden = item.hidden
                    ? '<span class="pill warn">Hidden</span>'
                    : '<span class="pill good">Visible</span>';

                var revenue = item.isRevenue === false
                    ? '<span class="pill warn">No</span>'
                    : '<span class="pill good">Yes</span>';

                var itemId = item.id || "";
                var itemName = item.name || "Unnamed Item";
                var priceDollars = (Number(item.price || 0) / 100).toFixed(2);

                row.innerHTML =
                    "<td><input class='name-input' id='name_" + escapeHtml(itemId) + "' value='" + escapeHtml(itemName) + "' /></td>" +
                    "<td><input class='small-input' id='price_" + escapeHtml(itemId) + "' value='" + escapeHtml(priceDollars) + "' /></td>" +
                    "<td class='muted'>" + escapeHtml(sku) + "</td>" +
                    "<td>" + available + "</td>" +
                    "<td>" + hidden + "</td>" +
                    "<td>" + revenue + "</td>" +
                    "<td class='muted'>" + formatDateFromClover(item.modifiedTime) + "</td>" +
                    "<td class='muted'>" + escapeHtml(itemId || "—") + "</td>" +
                    "<td><div class='row-actions'>" +
                        "<button type='button' class='btn btn-secondary' onclick='updateItem(\"" + escapeHtml(itemId) + "\")'>Save</button>" +
                        "<button type='button' class='btn btn-danger' onclick='deleteItem(\"" + escapeHtml(itemId) + "\")'>Delete</button>" +
                    "</div></td>";

                body.appendChild(row);
            });
        }

        async function fetchJson(url, options) {
            var response = await fetch(url, options || {});
            var data = await response.json();

            if (!response.ok) {
                var errorMessage = data && data.message ? data.message : "Request failed.";
                throw new Error(errorMessage);
            }

            return data;
        }

        async function checkHealth() {
            try {
                setBusy("Checking backend health...");
                var data = await fetchJson("/health");
                showResult(data);
                showToast("Backend is live.", "success");
            } catch (error) {
                showError(error);
            }
        }

        async function loadMerchant() {
            try {
                var connection = requireConnection();
                if (!connection) return;

                setBusy("Loading merchant info...");

                var data = await fetchJson(
                    "/clover-merchant?token=" + encodeURIComponent(connection.token) +
                    "&merchantId=" + encodeURIComponent(connection.merchantId)
                );

                showResult(data);
                updateStatusFromData();

                if (data.success) {
                    showToast("Merchant info loaded successfully.", "success");
                } else {
                    showToast(data.message || "Merchant test failed.", "error");
                }
            } catch (error) {
                showError(error);
            }
        }

        async function loadItems() {
            try {
                var connection = requireConnection();
                if (!connection) return;

                setBusy("Loading Clover inventory items...");

                var data = await fetchJson(
                    "/clover-items?token=" + encodeURIComponent(connection.token) +
                    "&merchantId=" + encodeURIComponent(connection.merchantId)
                );

                showResult(data);

                if (data.success) {
                    loadedItems = data.data && data.data.elements ? data.data.elements : [];
                    renderItems(loadedItems);
                    showToast("Clover inventory loaded: " + loadedItems.length + " item(s).", "success");
                } else {
                    showToast(data.message || "Failed to load Clover items.", "error");
                }
            } catch (error) {
                showError(error);
            }
        }

        async function createItem() {
            try {
                var connection = requireConnection();
                if (!connection) return;

                var nameBox = document.getElementById("itemName");
                var priceBox = document.getElementById("itemPrice");

                var name = nameBox && nameBox.value ? nameBox.value.trim() : "InvoiceRite Test Item";
                var price = priceBox && priceBox.value ? priceBox.value.trim() : "199";

                if (Number.isNaN(Number(price)) || Number(price) < 0) {
                    showToast("Price cents must be a valid positive number.", "error");
                    return;
                }

                setBusy("Creating Clover item...");

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

                if (data.success) {
                    showToast("Clover item created successfully.", "success");
                    await loadItems();
                } else {
                    showToast(data.message || "Failed to create item.", "error");
                }
            } catch (error) {
                showError(error);
            }
        }

        async function updateItem(itemId) {
            try {
                var connection = requireConnection();
                if (!connection) return;

                if (!itemId) {
                    showToast("Missing Clover item ID.", "error");
                    return;
                }

                var nameBox = document.getElementById("name_" + itemId);
                var priceBox = document.getElementById("price_" + itemId);

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

                setBusy("Updating Clover item...");

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
                showToast("Clover item updated.", "success");
                await loadItems();
            } catch (error) {
                showError(error);
            }
        }

        async function deleteItem(itemId) {
            try {
                var connection = requireConnection();
                if (!connection) return;

                if (!itemId) {
                    showToast("Missing Clover item ID.", "error");
                    return;
                }

                var ok = confirm("Delete this Clover item from the sandbox merchant?");
                if (!ok) return;

                setBusy("Deleting Clover item...");

                var data = await fetchJson(
                    "/clover-delete-item/" + encodeURIComponent(itemId) +
                    "?token=" + encodeURIComponent(connection.token) +
                    "&merchantId=" + encodeURIComponent(connection.merchantId),
                    { method: "POST" }
                );

                showResult(data);
                showToast("Clover item deleted.", "success");
                await loadItems();
            } catch (error) {
                showError(error);
            }
        }

        function prepareSyncPreview() {
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
                message: "Sync preview ready for future InvoiceRite desktop import.",
                count: preview.length,
                items: preview
            });

            showToast("Sync preview created. Desktop sync endpoint comes next.", "success");
        }

        if (embeddedConnection.connected && embeddedConnection.access_token && embeddedConnection.merchant_id) {
            showToast("Clover OAuth connection saved for this sandbox session.", "success");
        }

        window.checkHealth = checkHealth;
        window.loadMerchant = loadMerchant;
        window.loadItems = loadItems;
        window.createItem = createItem;
        window.updateItem = updateItem;
        window.deleteItem = deleteItem;
        window.applySearch = applySearch;
        window.prepareSyncPreview = prepareSyncPreview;
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

        const tokenResponse = await axios.post(
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
        console.error("Clover Root OAuth Error:");

        if (error.response?.data) {
            console.error(error.response.data);
        } else {
            console.error(error.message);
        }

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

        const merchantResponse = await axios.get(
            `${CLOVER_API_BASE_URL}/v3/merchants/${merchantId}`,
            {
                headers: cloverHeaders(accessToken)
            }
        );

        res.json({
            success: true,
            message: "Clover merchant info loaded successfully",
            data: merchantResponse.data
        });
    } catch (error) {
        console.error("Clover Merchant Error:", error.response?.data || error.message);

        res.status(error.response?.status || 500).json({
            success: false,
            message: "Failed to load Clover merchant info",
            error: error.response?.data || error.message
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

        const itemsResponse = await axios.get(
            `${CLOVER_API_BASE_URL}/v3/merchants/${merchantId}/items?limit=100`,
            {
                headers: cloverHeaders(accessToken)
            }
        );

        res.json({
            success: true,
            message: "Clover inventory items loaded successfully",
            data: itemsResponse.data
        });
    } catch (error) {
        console.error("Clover Items Error:", error.response?.data || error.message);

        res.status(error.response?.status || 500).json({
            success: false,
            message: "Failed to load Clover inventory items",
            error: error.response?.data || error.message
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

        if (!itemName || Number.isNaN(itemPrice) || itemPrice < 0) {
            return res.status(400).json({
                success: false,
                message: "Invalid item name or price."
            });
        }

        const createResponse = await axios.post(
            `${CLOVER_API_BASE_URL}/v3/merchants/${merchantId}/items`,
            {
                name: itemName,
                price: itemPrice,
                priceType: "FIXED",
                available: true,
                hidden: false,
                isRevenue: true
            },
            {
                headers: cloverHeaders(accessToken)
            }
        );

        res.json({
            success: true,
            message: "Clover item created successfully",
            data: createResponse.data
        });
    } catch (error) {
        console.error("Clover Create Item Error:", error.response?.data || error.message);

        res.status(error.response?.status || 500).json({
            success: false,
            message: "Failed to create Clover item",
            error: error.response?.data || error.message
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

        if (!itemName || Number.isNaN(itemPrice) || itemPrice < 0) {
            return res.status(400).json({
                success: false,
                message: "Invalid item name or price."
            });
        }

        const updateResponse = await axios.post(
            `${CLOVER_API_BASE_URL}/v3/merchants/${merchantId}/items/${itemId}`,
            {
                name: itemName,
                price: itemPrice,
                priceType: "FIXED",
                available: true,
                hidden: false,
                isRevenue: true
            },
            {
                headers: cloverHeaders(accessToken)
            }
        );

        res.json({
            success: true,
            message: "Clover item updated successfully",
            data: updateResponse.data
        });
    } catch (error) {
        console.error("Clover Update Item Error:", error.response?.data || error.message);

        res.status(error.response?.status || 500).json({
            success: false,
            message: "Failed to update Clover item",
            error: error.response?.data || error.message
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

        const deleteResponse = await axios.delete(
            `${CLOVER_API_BASE_URL}/v3/merchants/${merchantId}/items/${itemId}`,
            {
                headers: cloverHeaders(accessToken)
            }
        );

        res.json({
            success: true,
            message: "Clover item deleted successfully",
            data: deleteResponse.data || {}
        });
    } catch (error) {
        console.error("Clover Delete Item Error:", error.response?.data || error.message);

        res.status(error.response?.status || 500).json({
            success: false,
            message: "Failed to delete Clover item",
            error: error.response?.data || error.message
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

        if (!itemName || Number.isNaN(itemPrice) || itemPrice < 0) {
            return res.status(400).json({
                success: false,
                message: "Invalid item name or price."
            });
        }

        const createResponse = await axios.post(
            `${CLOVER_API_BASE_URL}/v3/merchants/${merchantId}/items`,
            {
                name: itemName,
                price: itemPrice,
                priceType: "FIXED",
                available: true,
                hidden: false,
                isRevenue: true
            },
            {
                headers: cloverHeaders(accessToken)
            }
        );

        res.json({
            success: true,
            message: "Clover test item created successfully",
            data: createResponse.data
        });
    } catch (error) {
        console.error("Clover Create Test Item Error:", error.response?.data || error.message);

        res.status(error.response?.status || 500).json({
            success: false,
            message: "Failed to create Clover test item",
            error: error.response?.data || error.message
        });
    }
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
