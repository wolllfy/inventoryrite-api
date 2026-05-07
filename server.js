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
| This is only for sandbox/testing.
| Render restarts will clear this.
| Later we can replace this with PostgreSQL/Supabase.
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

        .actions { display: flex; flex-wrap: wrap; gap: 12px; margin-top: 24px; }

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
        }

        .btn:hover { transform: translateY(-1px); }
        .btn:disabled { opacity: .58; cursor: not-allowed; transform: none; }

        .btn-primary { background: var(--green); color: white; box-shadow: 0 9px 20px rgba(21, 128, 61, 0.22); }
        .btn-primary:hover { background: var(--green-dark); }
        .btn-secondary { background: var(--blue-soft); color: #1d4ed8; }
        .btn-dark { background: #111827; color: white; }
        .btn-light { background: #f8fafc; color: #111827; border: 1px solid var(--line); }

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

        .table-wrap {
            border: 1px solid var(--line);
            border-radius: 16px;
            overflow: auto;
            background: white;
        }

        table { width: 100%; border-collapse: collapse; min-width: 850px; }
        th, td { padding: 13px 14px; border-bottom: 1px solid var(--line); text-align: left; font-size: 13px; }
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
                    creates test items, and gives you a clean starting point for a real Clover App Market product.
                </p>

                <div class="actions">
                    <a class="btn btn-primary" href="/connect-clover">Connect Clover</a>
                    <button class="btn btn-secondary" onclick="loadItems()">Load Clover Items</button>
                    <button class="btn btn-dark" onclick="createItem()">Create Test Item</button>
                    <button class="btn btn-light" onclick="checkHealth()">Check Backend</button>
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
                <h3>Sync Foundation</h3>
                <p>This is ready to become Clover to InvoiceRite desktop sync.</p>
            </div>
            <div class="card mini-card">
                <h3>App Market Ready</h3>
                <p>Clean onboarding, clear connection status, and professional UI.</p>
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
                    <button class="btn btn-secondary" onclick="loadMerchant()">Test Merchant</button>
                    <button class="btn btn-secondary" onclick="loadItems()">Load Items</button>
                </div>

                <button class="btn btn-primary" style="width:100%; margin-top:10px;" onclick="createItem()">Create Clover Item</button>
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
                    <p>Loaded Clover items will appear here in a clean table instead of only raw JSON.</p>
                </div>
                <button class="btn btn-secondary" onclick="loadItems()">Refresh Inventory</button>
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
                        </tr>
                    </thead>
                    <tbody id="itemsBody">
                        <tr>
                            <td colspan="8" class="empty">No items loaded yet. Click “Load Clover Items”.</td>
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
        const embeddedConnection = {
            connected: ${connected ? "true" : "false"},
            merchant_id: ${JSON.stringify(merchantId)},
            employee_id: ${JSON.stringify(employeeId)},
            access_token: ${JSON.stringify(accessToken)},
            connected_at: ${JSON.stringify(connectedAt)}
        };

        function getToken() {
            return document.getElementById("token").value.trim() || embeddedConnection.access_token || "";
        }

        function getMerchantId() {
            return document.getElementById("merchantId").value.trim() || embeddedConnection.merchant_id || "";
        }

        function centsToDollars(cents) {
            const value = Number(cents || 0) / 100;
            return value.toLocaleString(undefined, { style: "currency", currency: "USD" });
        }

        function formatDateFromClover(value) {
            if (!value) return "—";
            try {
                return new Date(Number(value)).toLocaleString();
            } catch {
                return "—";
            }
        }

        function showToast(message, type) {
            const wrap = document.getElementById("toastWrap");
            const toast = document.createElement("div");
            toast.className = "toast " + (type || "info");
            toast.textContent = message;
            wrap.appendChild(toast);
            setTimeout(function () {
                toast.remove();
            }, 4200);
        }

        function setBusy(buttonText) {
            document.getElementById("result").textContent = buttonText || "Loading...";
        }

        function showResult(data) {
            document.getElementById("result").textContent = JSON.stringify(data, null, 2);
        }

        function showError(error) {
            document.getElementById("result").textContent =
                "ERROR:\\n" + (error && error.message ? error.message : String(error));
            showToast(error && error.message ? error.message : "Request failed.", "error");
        }

        function requireConnection() {
            const token = getToken();
            const merchantId = getMerchantId();

            if (!token || !merchantId) {
                showToast("Please connect Clover or enter both token and merchant ID.", "error");
                return null;
            }

            return { token, merchantId };
        }

        function updateStatusFromData(data) {
            const merchantId = getMerchantId();
            if (merchantId) {
                document.getElementById("merchantDisplay").textContent = merchantId;
            }
        }

        function renderItems(items) {
            const body = document.getElementById("itemsBody");
            body.innerHTML = "";

            if (!items || !items.length) {
                body.innerHTML = '<tr><td colspan="8" class="empty">No Clover items found for this merchant.</td></tr>';
                return;
            }

            items.forEach(function (item) {
                const row = document.createElement("tr");

                const sku = item.sku || item.code || item.productCode || "—";
                const available = item.available === false
                    ? '<span class="pill warn">No</span>'
                    : '<span class="pill good">Yes</span>';
                const hidden = item.hidden
                    ? '<span class="pill warn">Hidden</span>'
                    : '<span class="pill good">Visible</span>';
                const revenue = item.isRevenue === false
                    ? '<span class="pill warn">No</span>'
                    : '<span class="pill good">Yes</span>';

                row.innerHTML =
                    "<td><strong>" + escapeHtml(item.name || "Unnamed Item") + "</strong></td>" +
                    "<td>" + centsToDollars(item.price || 0) + "</td>" +
                    "<td class='muted'>" + escapeHtml(sku) + "</td>" +
                    "<td>" + available + "</td>" +
                    "<td>" + hidden + "</td>" +
                    "<td>" + revenue + "</td>" +
                    "<td class='muted'>" + formatDateFromClover(item.modifiedTime) + "</td>" +
                    "<td class='muted'>" + escapeHtml(item.id || "—") + "</td>";

                body.appendChild(row);
            });
        }

        function escapeHtml(value) {
            return String(value || "")
                .replaceAll("&", "&amp;")
                .replaceAll("<", "&lt;")
                .replaceAll(">", "&gt;")
                .replaceAll('"', "&quot;")
                .replaceAll("'", "&#039;");
        }

        async function checkHealth() {
            try {
                setBusy("Checking backend health...");
                const response = await fetch("/health");
                const data = await response.json();
                showResult(data);
                showToast("Backend is live.", "success");
            } catch (error) {
                showError(error);
            }
        }

        async function loadMerchant() {
            try {
                const connection = requireConnection();
                if (!connection) return;

                setBusy("Loading merchant info...");

                const response = await fetch(
                    "/clover-merchant?token=" + encodeURIComponent(connection.token) +
                    "&merchantId=" + encodeURIComponent(connection.merchantId)
                );

                const data = await response.json();
                showResult(data);
                updateStatusFromData(data);

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
                const connection = requireConnection();
                if (!connection) return;

                setBusy("Loading Clover inventory items...");

                const response = await fetch(
                    "/clover-items?token=" + encodeURIComponent(connection.token) +
                    "&merchantId=" + encodeURIComponent(connection.merchantId)
                );

                const data = await response.json();
                showResult(data);

                if (data.success) {
                    const items = data.data && data.data.elements ? data.data.elements : [];
                    renderItems(items);
                    showToast("Clover inventory loaded: " + items.length + " item(s).", "success");
                } else {
                    showToast(data.message || "Failed to load Clover items.", "error");
                }
            } catch (error) {
                showError(error);
            }
        }

        async function createItem() {
            try {
                const connection = requireConnection();
                if (!connection) return;

                const name = document.getElementById("itemName").value.trim() || "InvoiceRite Test Item";
                const price = document.getElementById("itemPrice").value.trim() || "199";

                if (Number.isNaN(Number(price)) || Number(price) < 0) {
                    showToast("Price cents must be a valid positive number.", "error");
                    return;
                }

                setBusy("Creating Clover item...");

                const response = await fetch(
                    "/clover-create-item?token=" + encodeURIComponent(connection.token) +
                    "&merchantId=" + encodeURIComponent(connection.merchantId),
                    {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ name: name, price: Number(price) })
                    }
                );

                const data = await response.json();
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

        if (embeddedConnection.connected && embeddedConnection.access_token && embeddedConnection.merchant_id) {
            showToast("Clover OAuth connection saved for this sandbox session.", "success");
        }
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
                headers: {
                    Authorization: `Bearer ${accessToken}`
                }
            }
        );

        res.json({
            success: true,
            message: "Clover merchant info loaded successfully",
            data: merchantResponse.data
        });
    } catch (error) {
        console.error("Clover Merchant Error:", error.response?.data || error.message);

        res.status(500).json({
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
                headers: {
                    Authorization: `Bearer ${accessToken}`
                }
            }
        );

        res.json({
            success: true,
            message: "Clover inventory items loaded successfully",
            data: itemsResponse.data
        });
    } catch (error) {
        console.error("Clover Items Error:", error.response?.data || error.message);

        res.status(500).json({
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

        const itemName = req.body.name || "InvoiceRite Test Item";
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
                headers: {
                    Authorization: `Bearer ${accessToken}`,
                    "Content-Type": "application/json"
                }
            }
        );

        res.json({
            success: true,
            message: "Clover item created successfully",
            data: createResponse.data
        });
    } catch (error) {
        console.error("Clover Create Item Error:", error.response?.data || error.message);

        res.status(500).json({
            success: false,
            message: "Failed to create Clover item",
            error: error.response?.data || error.message
        });
    }
});

/*
|--------------------------------------------------------------------------
| CLOVER CREATE TEST ITEM ROUTE - GET
| Kept for backwards compatibility with your older button/link tests.
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

        const itemName = req.query.name || "InvoiceRite Test Item";
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
                headers: {
                    Authorization: `Bearer ${accessToken}`,
                    "Content-Type": "application/json"
                }
            }
        );

        res.json({
            success: true,
            message: "Clover test item created successfully",
            data: createResponse.data
        });
    } catch (error) {
        console.error("Clover Create Test Item Error:", error.response?.data || error.message);

        res.status(500).json({
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
