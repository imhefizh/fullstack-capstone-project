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