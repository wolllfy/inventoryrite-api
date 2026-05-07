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

const REDIRECT_URI = "https://inventoryrite-api.onrender.com/";

const CLOVER_BASE_URL = "https://sandbox.dev.clover.com";
const CLOVER_API_BASE_URL = "https://apisandbox.dev.clover.com";

/*
|--------------------------------------------------------------------------
| ROOT + CLOVER CALLBACK HANDLER
|--------------------------------------------------------------------------
*/

app.get("/", async (req, res) => {

    try {

        const code = req.query.code;

        if (!code) {
            return res.send("InventoryRite API is running.");
        }

        console.log("Clover OAuth code received.");

        // FIXED TOKEN ENDPOINT
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

        console.log("FULL TOKEN DATA:");
        console.log(tokenData);

        res.json({
            success: true,
            message: "Clover connected successfully",
            merchant_id: req.query.merchant_id || null,
            employee_id: req.query.employee_id || null,
            data: tokenData
        });

    } catch (error) {

        console.error("Clover Root OAuth Error:");

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
| HEALTH ROUTE
|--------------------------------------------------------------------------
*/

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

app.listen(PORT, () => {

    console.log(`Server running on port ${PORT}`);

});
