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
const CLOVER_BASE_URL = "https://sandbox.dev.clover.com";

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

app.get("/connect-clover", (req, res) => {
    if (!CLOVER_CLIENT_ID) {
        return res.status(500).json({
            success: false,
            message: "Missing CLOVER_CLIENT_ID in Render environment variables."
        });
    }

    const cloverAuthUrl =
        `${CLOVER_BASE_URL}/oauth/authorize` +
        `?client_id=${encodeURIComponent(CLOVER_CLIENT_ID)}` +
        `&response_type=code` +
        `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}`;

    res.redirect(cloverAuthUrl);
});

app.get("/oauth/callback", async (req, res) => {
    try {
        const code = req.query.code;
        const merchantId = req.query.merchant_id || req.query.merchantId;

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

        const response = await axios.post(
            `${CLOVER_BASE_URL}/oauth/token`,
            null,
            {
                params: {
                    client_id: CLOVER_CLIENT_ID,
                    client_secret: CLOVER_CLIENT_SECRET,
                    code: code
                }
            }
        );

        const tokenData = response.data;

        console.log("Clover connected successfully.");
        console.log({
            merchantId: merchantId || tokenData.merchant_id || null,
            hasAccessToken: !!tokenData.access_token,
            hasRefreshToken: !!tokenData.refresh_token
        });

        res.json({
            success: true,
            message: "Clover connected successfully",
            merchantId: merchantId || tokenData.merchant_id || null,
            data: tokenData
        });

    } catch (error) {
        console.error("Clover OAuth Error:");
        console.error(error.response?.data || error.message);

        res.status(500).json({
            success: false,
            message: "Clover OAuth failed",
            error: error.response?.data || error.message
        });
    }
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});