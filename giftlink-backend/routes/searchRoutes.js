const express = require('express');
const router = express.Router();
const connectToDatabase = require('../models/db');

// Search for gifts
router.get('/', async (req, res, next) => {
    console.log("Someone trying to search")
    try {
        const db = await connectToDatabase();
        
        const collection = db.collection("gifts");
        
        // Initialize the query object
        let query = {};
        
        // Add the name filter to the query if the name parameter is not empty
        if (req.query.name && req.query.name.trim() !== "") {
            query.name = { $regex: req.query.name, $options: "i" };
            // query.name = req.query.name;
        }
        
        // Task 3: Add other filters to the query
        if (req.query.category) {
            query.category = req.query.category;
        }
        if (req.query.condition) {
            query.condition = req.query.condition;
        }
        if (req.query.age_years) {
            query.age_years = { $lte: parseInt(req.query.age_years) };
        }
        
        console.log(query)
        // Task 4: Fetch filtered gifts using the find(query) method. Make sure to use await and store the result in the `gifts` constant
        const gifts = await collection.find(query).toArray();
        
        console.log(gifts)
        res.json(gifts);
    } catch (e) {
        next(e);
    }
});

module.exports = router;