const express = require("express");
const cors = require("cors");
const axios = require("axios");
require("dotenv").config();

const app = express();

app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;

app.get("/", (req, res) => {
    res.send("InventoryRite API is running.");
});

app.get("/health", (req, res) => {
    res.json({
        success: true,
        message: "InventoryRite backend healthy"
    });
});

/*
|--------------------------------------------------------------------------
| Clover Connect Route
|--------------------------------------------------------------------------
*/

app.get("/connect-clover", (req, res) => {

    const clientId = process.env.CLOVER_CLIENT_ID;

    const redirectUri =
        "https://inventoryrite-api.onrender.com/oauth/callback";

    const cloverAuthUrl =
        `https://sandbox.dev.clover.com/oauth/authorize` +
        `?client_id=${clientId}` +
        `&response_type=code` +
        `&redirect_uri=${encodeURIComponent(redirectUri)}`;

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

        const response = await axios.post(
            "https://sandbox.dev.clover.com/oauth/token",
            null,
            {
                params: {
                    client_id: process.env.CLOVER_CLIENT_ID,
                    client_secret: process.env.CLOVER_CLIENT_SECRET,
                    code: code
                }
            }
        );

        const tokenData = response.data;

        console.log("Clover Token Response:");
        console.log(tokenData);

        res.json({
            success: true,
            message: "Clover connected successfully",
            data: tokenData
        });

    } catch (error) {

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