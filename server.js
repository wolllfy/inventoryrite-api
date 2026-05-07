const express = require("express");
const cors = require("cors");
const axios = require("axios");
require("dotenv").config();

const app = express();

app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;

const CLOVER_CLIENT_ID = process.env.CLOVER_CLIENT_ID?.trim();
const CLOVER_CLIENT_SECRET = process.env.CLOVER_CLIENT_SECRET?.trim();

const REDIRECT_URI = "https://inventoryrite-api.onrender.com/oauth/callback";
const CLOVER_BASE_URL = "https://www.sandbox.dev.clover.com";

app.get("/", (req, res) => {
    res.send("InventoryRite API is running.");
});

app.get("/health", (req, res) => {
    res.json({
        success: true,
        message: "InventoryRite backend healthy",
        cloverClientIdLoaded: !!CLOVER_CLIENT_ID,
        cloverSecretLoaded: !!CLOVER_CLIENT_SECRET
    });
});

/*
|--------------------------------------------------------------------------
| Clover Connect Route
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
| Clover OAuth Callback
|--------------------------------------------------------------------------
*/

app.get("/oauth/callback", async (req, res) => {

    try {

        const code = req.query.code;

        if (!code) {
            return res.status(400).json({
                success: false,
                message: "Missing Clover authorization code"
            });
        }

        if (!CLOVER_CLIENT_ID || !CLOVER_CLIENT_SECRET) {
            return res.status(500).json({
                success: false,
                message: "Missing Clover environment variables.",
                cloverClientIdLoaded: !!CLOVER_CLIENT_ID,
                cloverSecretLoaded: !!CLOVER_CLIENT_SECRET
            });
        }

        console.log("Starting Clover token exchange...");

        const tokenResponse = await axios.post(
            `${CLOVER_BASE_URL}/oauth/token`,
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

        console.log("Clover OAuth successful.");
        console.log({
            hasAccessToken: !!tokenData.access_token,
            hasRefreshToken: !!tokenData.refresh_token,
            merchantId: tokenData.merchant_id || null
        });

        res.json({
            success: true,
            message: "Clover connected successfully",
            data: tokenData
        });

    } catch (error) {

        console.error("Clover OAuth Error:");

        if (error.response?.data) {
            console.error(error.response.data);
        } else {
            console.error(error.message);
        }

        res.status(500).json({
            success: false,
            message: "Clover OAuth failed",
            error: error.response?.data || error.message
        });
    }
});

/*
|--------------------------------------------------------------------------
| Clover Inventory Items Route
|--------------------------------------------------------------------------
| Test format:
| https://inventoryrite-api.onrender.com/clover-items?token=YOUR_ACCESS_TOKEN
|--------------------------------------------------------------------------
*/

app.get("/clover-items", async (req, res) => {

    try {

        const accessToken = req.query.token;

        if (!accessToken) {
            return res.status(400).json({
                success: false,
                message: "Missing Clover access token. Add ?token=YOUR_ACCESS_TOKEN to the URL."
            });
        }

        const itemsResponse = await axios.get(
            `${CLOVER_BASE_URL}/v3/merchants/me/items`,
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

        if (error.response?.data) {
            console.error(error.response.data);
        } else {
            console.error(error.message);
        }

        res.status(500).json({
            success: false,
            message: "Failed to load Clover inventory items",
            error: error.response?.data || error.message
        });
    }
});

/*
|--------------------------------------------------------------------------
| Clover Merchant Info Route
|--------------------------------------------------------------------------
| Test format:
| https://inventoryrite-api.onrender.com/clover-merchant?token=YOUR_ACCESS_TOKEN
|--------------------------------------------------------------------------
*/

app.get("/clover-merchant", async (req, res) => {

    try {

        const accessToken = req.query.token;

        if (!accessToken) {
            return res.status(400).json({
                success: false,
                message: "Missing Clover access token. Add ?token=YOUR_ACCESS_TOKEN to the URL."
            });
        }

        const merchantResponse = await axios.get(
            `${CLOVER_BASE_URL}/v3/merchants/me`,
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

        if (error.response?.data) {
            console.error(error.response.data);
        } else {
            console.error(error.message);
        }

        res.status(500).json({
            success: false,
            message: "Failed to load Clover merchant info",
            error: error.response?.data || error.message
        });
    }
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
