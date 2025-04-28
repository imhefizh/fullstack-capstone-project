const express = require('express')
const bcryptjs = require('bcryptjs')
const jwt = require('jsonwebtoken')
const { body, validationResult} = require('express-validator') 
const connectToDatabase = require('../models/db.js')
const router = express.Router();
const dotenv = require('dotenv')
const pino = require('pino')

dotenv.config();

const JWT_SECRET = process.env.JWT_SECRET;

router.post('/register', async (req, res) => {
    try {
        // Konek ke database
        const db = await connectToDatabase();
        const collection = db.collection('users')
        // Ambil email dari request body
        const email = req.body.email
        // Cek apakah email sudah dipakai
        const doesEmailExist = await collection.findOne({email: email}).toArray()
        
        // Hashing password
        const password = req.body.password
        const salt = await bcryptjs.genSalt(10)
        const hash = await bcryptjs.hash(password, salt)


        // Menyimpan akun
        const newUser = await collection.insertOne({
            email: email, 
            firstName: req.body.firstName,
            lastName: req.body.lastName,
            password: hash,
            createdAt: new Date(),
        })

        // Membuat autentikasi JWT
        const payload = {
            user: {
                id: newUser.insertedId,
            },
        };
        const authtoken = jwt.sign(payload, JWT_SECRET);

        logger.info('User registered successfully');
        res.json({authtoken, email})
    } catch (err) {
        return res.status(500).send('Internal server error')
    }
})

router.post('/login', async (req, res) => {
    try {
        const db = await connectToDatabase();
        const collection = db.collection('users')
        const email = req.body.email
        const password = req.body.password
        const doesEmailExists = await collection.findOne({email: email});

        if (doesEmailExists) {
            let result = await bcryptjs.compare(password, doesEmailExists.password)
            if(!result) {
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

    }   catch (e) {
            logger.error(e);
            return res.status(500).send('Internal server error');
        }
});

module.exports = router;