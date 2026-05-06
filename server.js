const express = require("express");
const cors = require("cors");
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

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});