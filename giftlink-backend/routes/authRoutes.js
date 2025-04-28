const express = require('express');
const bcryptjs = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { validationResult } = require('express-validator');
const connectToDatabase = require('../models/db.js');
const router = express.Router();
const dotenv = require('dotenv');
const logger = require('../logger.js');

dotenv.config();

const JWT_SECRET = process.env.JWT_SECRET;

router.post('/register', async (req, res) => {
    try {
        const db = await connectToDatabase();
        const collection = db.collection('users');
        const email = req.body.email;

        const doesEmailExist = await collection.findOne({ email: email });
        console.log("Kita bakal masuk ke inti proses")
        console.log(!doesEmailExist)
        if (!doesEmailExist) {
            console.log("Checkout 0")
            const password = req.body.password;
            console.log(password)
            console.log(email)
            const salt = await bcryptjs.genSalt(10);
            const hash = await bcryptjs.hash(password, salt);
            console.log("Checkpoint 1")

            const newUser = {
                email: email,
                firstName: req.body.firstName,
                lastName: req.body.lastName,
                password: hash,
                createdAt: new Date(),
            };
            console.log(newUser);

            await collection.insertOne(newUser);

            console.log("Checkpoint 2")
            const payload = {
                user: {
                    id: newUser.insertedId,
                },
            };
            const authtoken = jwt.sign(payload, JWT_SECRET);
            console.log("Checkpoint 3")
            logger.info('User registered successfully');
            res.json({ authtoken, email });
        } else {
            res.send('Email already exists');
        }
    } catch (err) {
        console.log("Error");
        return res.status(500).send('Internal server error');
    }
});

router.post('/login', async (req, res) => {
    console.log("Ada yang mau login")
    try {
        console.log("Ayo bekerja")
        const db = await connectToDatabase();
        const collection = db.collection('users');
        const email = req.body.email;
        const password = req.body.password;
        const doesEmailExists = await collection.findOne({ email: email });
        console.log("Checkpoint 1")
        console.log(doesEmailExists)

        if (doesEmailExists) {
            let result = await bcryptjs.compare(password, doesEmailExists.password);
            if (!result) {
                logger.error('Passwords do not match');
                return res.status(404).json({ error: 'Wrong pasword' });
            }
            const userName = doesEmailExists.firstName;
            const userEmail = doesEmailExists.email;

            const payload = {
                user: {
                    id: doesEmailExists._id.toString(),
                },
            };
            const authtoken = jwt.sign(payload, JWT_SECRET);
            logger.info('User logged in successfully');
            return res.status(200).json({ authtoken, userName, userEmail });
        } else {
            logger.error('User not found');
            return res.status(404).json({ error: 'User not found' });
        }

    } catch (e) {
        logger.error(e);
        return res.status(500).send('Internal server error');
    }
});


router.put('/update', async (req, res) => {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
        logger.error('Validation errors in update request', errors.array());
        return res.status(400).json({ errors: errors.array() });
    }

    try {

        const email = req.headers.email;
        if (!email) {
            logger.error('Email not found in the request headers');
            return res.status(400).json({ error: "Email not found in the request headers" });
        }

        const db = connectToDatabase();
        const collection = db.collection('users');

        const existingUser = collection.findOne({ email });

        if (!existingUser) {
            logger.error('User not found');
            return res.status(404).json({ error: "User not found" });
        }

        existingUser.firstName = req.body.name;
        existingUser.updatedAt = new Date();

        const updatedUser = await collection.findOneAndUpdate(
            { email },
            { $set: existingUser },
            { returnDocument: 'after' }
        );

        const payload = {
            user: {
                id: updatedUser._id.toString(),
            }
        };
        const authtoken = jwt.sign(payload, JWT_SECRET);
        logger.info('User updated successfully');

        res.json({ authtoken });
    } catch (e) {
        logger.error(e);
        return res.status(500).send('Internal server error');
    }
});

module.exports = router;