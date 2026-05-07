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
| Later we can replace this with a real database.
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
| UI HELPER
|--------------------------------------------------------------------------
*/

function renderDashboard(options = {}) {

    const merchantId = options.merchant_id || latestCloverConnection.merchant_id || "";
    const employeeId = options.employee_id || latestCloverConnection.employee_id || "";
    const accessToken = options.access_token || latestCloverConnection.access_token || "";
    const connected = !!accessToken || latestCloverConnection.connected;

    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>InventoryRite Clover App</title>
    <style>
        :root {
            --bg: #f5f7fb;
            --card: #ffffff;
            --text: #111827;
            --muted: #6b7280;
            --line: #e5e7eb;
            --green: #15803d;
            --green-dark: #166534;
            --blue: #2563eb;
            --red: #b91c1c;
            --amber: #b45309;
            --shadow: 0 14px 40px rgba(15, 23, 42, 0.08);
            --radius: 18px;
        }

        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            font-family: Arial, Helvetica, sans-serif;
            background: radial-gradient(circle at top left, #e9f7ef, transparent 34%),
                        linear-gradient(180deg, #f8fafc 0%, #eef2f7 100%);
            color: var(--text);
        }

        .topbar {
            background: #ffffff;
            border-bottom: 1px solid var(--line);
            padding: 18px 28px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            position: sticky;
            top: 0;
            z-index: 20;
        }

        .brand {
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .logo {
            width: 42px;
            height: 42px;
            border-radius: 12px;
            background: linear-gradient(135deg, #16a34a, #14532d);
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: 800;
            letter-spacing: -1px;
            box-shadow: 0 8px 20px rgba(21, 128, 61, 0.25);
        }

        .brand h1 {
            margin: 0;
            font-size: 21px;
            line-height: 1.1;
        }

        .brand p {
            margin: 3px 0 0;
            color: var(--muted);
            font-size: 13px;
        }

        .badge {
            padding: 8px 12px;
            border-radius: 999px;
            font-size: 13px;
            font-weight: 700;
            border: 1px solid var(--line);
            background: #f9fafb;
        }

        .badge.connected {
            background: #ecfdf5;
            color: #166534;
            border-color: #bbf7d0;
        }

        .badge.disconnected {
            background: #fff7ed;
            color: #9a3412;
            border-color: #fed7aa;
        }

        .wrap {
            max-width: 1180px;
            margin: 28px auto;
            padding: 0 22px 50px;
        }

        .hero {
            display: grid;
            grid-template-columns: 1.4fr 0.8fr;
            gap: 22px;
            align-items: stretch;
            margin-bottom: 22px;
        }

        .card {
            background: var(--card);
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
            width: 260px;
            height: 260px;
            border-radius: 50%;
            right: -80px;
            top: -90px;
            background: rgba(34, 197, 94, 0.12);
        }

        .eyebrow {
            color: var(--green);
            font-weight: 800;
            letter-spacing: .08em;
            text-transform: uppercase;
            font-size: 12px;
            margin-bottom: 10px;
        }

        .hero h2 {
            margin: 0;
            font-size: 34px;
            line-height: 1.08;
            letter-spacing: -0.03em;
        }

        .hero-text {
            margin: 15px 0 0;
            color: var(--muted);
            line-height: 1.6;
            max-width: 670px;
            font-size: 15px;
        }

        .actions {
            display: flex;
            flex-wrap: wrap;
            gap: 12px;
            margin-top: 24px;
        }

        .btn {
            border: 0;
            border-radius: 12px;
            padding: 12px 16px;
            font-weight: 800;
            cursor: pointer;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            min-height: 44px;
            transition: transform .12s ease, box-shadow .12s ease;
        }

        .btn:hover {
            transform: translateY(-1px);
        }

        .btn-primary {
            background: var(--green);
            color: white;
            box-shadow: 0 8px 18px rgba(21, 128, 61, 0.22);
        }

        .btn-primary:hover {
            background: var(--green-dark);
        }

        .btn-secondary {
            background: #eef2ff;
            color: #1d4ed8;
        }

        .btn-dark {
            background: #111827;
            color: white;
        }

        .status-card {
            padding: 24px;
        }

        .status-row {
            display: flex;
            justify-content: space-between;
            gap: 14px;
            border-bottom: 1px solid var(--line);
            padding: 13px 0;
        }

        .status-row:last-child {
            border-bottom: 0;
        }

        .status-label {
            color: var(--muted);
            font-size: 13px;
        }

        .status-value {
            font-weight: 800;
            font-size: 13px;
            text-align: right;
            word-break: break-all;
        }

        .grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 18px;
            margin-bottom: 22px;
        }

        .mini-card {
            padding: 22px;
        }

        .mini-card h3 {
            margin: 0 0 8px;
            font-size: 18px;
        }

        .mini-card p {
            margin: 0;
            color: var(--muted);
            line-height: 1.5;
            font-size: 14px;
        }

        .workbench {
            display: grid;
            grid-template-columns: 0.95fr 1.05fr;
            gap: 22px;
        }

        .panel {
            padding: 24px;
        }

        .panel h3 {
            margin: 0 0 8px;
            font-size: 21px;
        }

        .panel-desc {
            margin: 0 0 18px;
            color: var(--muted);
            line-height: 1.5;
            font-size: 14px;
        }

        label {
            display: block;
            font-size: 13px;
            font-weight: 800;
            margin-bottom: 7px;
        }

        input {
            width: 100%;
            border: 1px solid #d1d5db;
            border-radius: 12px;
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

        .result {
            background: #0f172a;
            color: #e5e7eb;
            border-radius: 14px;
            padding: 18px;
            min-height: 260px;
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
            border-radius: 12px;
            font-size: 13px;
            line-height: 1.45;
            margin-top: 14px;
        }

        .footer {
            color: var(--muted);
            text-align: center;
            margin-top: 30px;
            font-size: 13px;
        }

        @media (max-width: 900px) {
            .hero,
            .workbench,
            .grid {
                grid-template-columns: 1fr;
            }

            .hero h2 {
                font-size: 28px;
            }

            .topbar {
                align-items: flex-start;
                gap: 14px;
                flex-direction: column;
            }
        }
    </style>
</head>
<body>

    <div class="topbar">
        <div class="brand">
            <div class="logo">IR</div>
            <div>
                <h1>InventoryRite Clover App</h1>
                <p>Simple inventory connector for Clover merchants</p>
            </div>
        </div>

        <div class="badge ${connected ? "connected" : "disconnected"}">
            ${connected ? "Connected to Clover" : "Not Connected"}
        </div>
    </div>

    <main class="wrap">

        <section class="hero">
            <div class="card hero-main">
                <div class="eyebrow">Clover Sandbox App</div>
                <h2>Manage Clover inventory through your InventoryRite connector.</h2>
                <p class="hero-text">
                    This lightweight dashboard confirms that the merchant connection is working,
                    reads Clover inventory, and creates test items through your live Render backend.
                </p>

                <div class="actions">
                    <a class="btn btn-primary" href="/connect-clover">Connect Clover</a>
                    <button class="btn btn-secondary" onclick="loadItems()">Load Clover Items</button>
                    <button class="btn btn-dark" onclick="createItem()">Create Test Item</button>
                </div>

                <div class="note">
                    For this sandbox version, paste your Clover Merchant API token below.
                    Later, this can be stored securely in a database.
                </div>
            </div>

            <div class="card status-card">
                <div class="status-row">
                    <div class="status-label">Merchant ID</div>
                    <div class="status-value" id="merchantDisplay">${merchantId || "Not detected"}</div>
                </div>
                <div class="status-row">
                    <div class="status-label">Employee ID</div>
                    <div class="status-value">${employeeId || "Not detected"}</div>
                </div>
                <div class="status-row">
                    <div class="status-label">Backend</div>
                    <div class="status-value">Render Live</div>
                </div>
                <div class="status-row">
                    <div class="status-label">Mode</div>
                    <div class="status-value">Sandbox</div>
                </div>
            </div>
        </section>

        <section class="grid">
            <div class="card mini-card">
                <h3>Read Items</h3>
                <p>Pull item data from Clover inventory and display the API response instantly.</p>
            </div>

            <div class="card mini-card">
                <h3>Create Items</h3>
                <p>Create a Clover inventory item from this dashboard or later from InvoiceRite desktop.</p>
            </div>

            <div class="card mini-card">
                <h3>Ready to Extend</h3>
                <p>Add orders, payments, customers, sync logs, and merchant onboarding later.</p>
            </div>
        </section>

        <section class="workbench">
            <div class="card panel">
                <h3>Connection Test</h3>
                <p class="panel-desc">
                    Paste your merchant API token, keep the merchant ID filled in, then test inventory.
                </p>

                <label for="token">Merchant API Token</label>
                <input id="token" type="password" placeholder="Paste Clover Merchant API token here" />

                <label for="merchantId">Merchant ID</label>
                <input id="merchantId" type="text" value="${merchantId || ""}" placeholder="Example: 7E2G3TE77A091" />

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

                <button class="btn btn-secondary" style="width:100%; margin-bottom:10px;" onclick="loadMerchant()">Test Merchant</button>
                <button class="btn btn-secondary" style="width:100%; margin-bottom:10px;" onclick="loadItems()">Load Clover Items</button>
                <button class="btn btn-primary" style="width:100%;" onclick="createItem()">Create Clover Item</button>
            </div>

            <div class="card panel">
                <h3>Live API Result</h3>
                <p class="panel-desc">
                    Results from your Render backend will appear here.
                </p>
                <pre class="result" id="result">Ready. Paste your merchant API token and click a button.</pre>
            </div>
        </section>

        <div class="footer">
            InventoryRite Clover Connector · Sandbox Build · Process Rite Inc
        </div>

    </main>

    <script>
        function getToken() {
            return document.getElementById("token").value.trim();
        }

        function getMerchantId() {
            return document.getElementById("merchantId").value.trim();
        }

        function showResult(data) {
            document.getElementById("result").textContent = JSON.stringify(data, null, 2);
        }

        function showError(error) {
            document.getElementById("result").textContent =
                "ERROR:\\n" + (error && error.message ? error.message : String(error));
        }

        async function loadMerchant() {
            try {
                const token = getToken();
                const merchantId = getMerchantId();

                if (!token || !merchantId) {
                    alert("Please enter token and merchant ID.");
                    return;
                }

                const response = await fetch("/clover-merchant?token=" + encodeURIComponent(token) + "&merchantId=" + encodeURIComponent(merchantId));
                const data = await response.json();
                showResult(data);
            } catch (error) {
                showError(error);
            }
        }

        async function loadItems() {
            try {
                const token = getToken();
                const merchantId = getMerchantId();

                if (!token || !merchantId) {
                    alert("Please enter token and merchant ID.");
                    return;
                }

                const response = await fetch("/clover-items?token=" + encodeURIComponent(token) + "&merchantId=" + encodeURIComponent(merchantId));
                const data = await response.json();
                showResult(data);
            } catch (error) {
                showError(error);
            }
        }

        async function createItem() {
            try {
                const token = getToken();
                const merchantId = getMerchantId();
                const name = document.getElementById("itemName").value.trim() || "InvoiceRite Test Item";
                const price = document.getElementById("itemPrice").value.trim() || "199";

                if (!token || !merchantId) {
                    alert("Please enter token and merchant ID.");
                    return;
                }

                const url =
                    "/clover-create-test-item?token=" + encodeURIComponent(token) +
                    "&merchantId=" + encodeURIComponent(merchantId) +
                    "&name=" + encodeURIComponent(name) +
                    "&price=" + encodeURIComponent(price);

                const response = await fetch(url);
                const data = await response.json();
                showResult(data);
            } catch (error) {
                showError(error);
            }
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
            merchant_id: req.query.merchant_id || "",
            employee_id: req.query.employee_id || "",
            access_token: tokenData.access_token || "",
            connected_at: new Date().toISOString()
        };

        console.log("Clover connected successfully.");
        console.log({
            merchant_id: latestCloverConnection.merchant_id,
            employee_id: latestCloverConnection.employee_id,
            hasAccessToken: !!latestCloverConnection.access_token
        });

        res.send(renderDashboard({
            merchant_id: latestCloverConnection.merchant_id,
            employee_id: latestCloverConnection.employee_id,
            access_token: latestCloverConnection.access_token
        }));

    } catch (error) {

        console.error("Clover Root OAuth Error:");

        if (error.response?.data) {
            console.error(error.response.data);
        } else {
            console.error(error.message);
        }

        res.status(500).send(`
            <h1>Clover OAuth failed</h1>
            <pre>${JSON.stringify(error.response?.data || error.message, null, 2)}</pre>
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
            connected_at: latestCloverConnection.connected_at
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

    res.redirect(cloverAuthUrl);

});

/*
|--------------------------------------------------------------------------
| CLOVER MERCHANT INFO ROUTE
|--------------------------------------------------------------------------
*/

app.get("/clover-merchant", async (req, res) => {

    try {

        const accessToken = req.query.token;
        const merchantId = req.query.merchantId;

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

        console.error("Clover Merchant Error:");

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

        const accessToken = req.query.token;
        const merchantId = req.query.merchantId;

        if (!accessToken || !merchantId) {

            return res.status(400).json({
                success: false,
                message: "Missing token or merchantId."
            });

        }

        const itemsResponse = await axios.get(
            `${CLOVER_API_BASE_URL}/v3/merchants/${merchantId}/items`,
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

        console.error("Clover Items Error:");

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

        const accessToken = req.query.token;
        const merchantId = req.query.merchantId;

        if (!accessToken || !merchantId) {

            return res.status(400).json({
                success: false,
                message: "Missing token or merchantId."
            });

        }

        const itemName = req.body.name || "InvoiceRite Test Item";
        const itemPrice = Number(req.body.price || 199);

        if (!itemName || Number.isNaN(itemPrice)) {

            return res.status(400).json({
                success: false,
                message: "Invalid item name or price."
            });

        }

        const createResponse = await axios.post(
            `${CLOVER_API_BASE_URL}/v3/merchants/${merchantId}/items`,
            {
                name: itemName,
                price: itemPrice
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

        console.error("Clover Create Item Error:");

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
|--------------------------------------------------------------------------
*/

app.get("/clover-create-test-item", async (req, res) => {

    try {

        const accessToken = req.query.token;
        const merchantId = req.query.merchantId;

        if (!accessToken || !merchantId) {

            return res.status(400).json({
                success: false,
                message: "Missing token or merchantId."
            });

        }

        const itemName = req.query.name || "InvoiceRite Test Item";
        const itemPrice = Number(req.query.price || 199);

        if (!itemName || Number.isNaN(itemPrice)) {

            return res.status(400).json({
                success: false,
                message: "Invalid item name or price."
            });

        }

        const createResponse = await axios.post(
            `${CLOVER_API_BASE_URL}/v3/merchants/${merchantId}/items`,
            {
                name: itemName,
                price: itemPrice
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

        console.error("Clover Create Test Item Error:");

        res.status(500).json({
            success: false,
            message: "Failed to create Clover test item",
            error: error.response?.data || error.message
        });

    }

});

app.listen(PORT, () => {

    console.log(`Server running on port ${PORT}`);

});
