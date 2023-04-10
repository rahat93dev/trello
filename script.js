пример реализации маршрута /user/sign-upс необходимым функционалом:

    JavaScript

Скопировать код
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('../models/User');

const router = express.Router();

router.post('/user/sign-up', async (req, res) => {
    const { email, password } = req.body;

    // Check if email and password are present in request body
    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
    }

    try {
        // Check if user with such email already exists
        const userExists = await User.findOne({ email });
        if (userExists) {
            return res.status(400).json({ error: 'Email is already taken' });
        }

        // Encrypt password using bcrypt
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create new user instance
        const user = new User({ email, password: hashedPassword });

        // Save user to database
        await user.save();

        // Create JWT token
        const token = jwt.sign({ userId: user._id }, 'my_secret_key');

        // Return token to client
        return res.json({ token });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ error: 'Server error' });
    }
});

module.exports = router;
А вот пример реализации модели с хуком и методом Userперед сохранением :comparePassword

JavaScript

Скопировать код
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
});

userSchema.pre('save', async function(next) {
    const user = this;
    if (!user.isModified('password')) {
        return next();
    }

    try {
        // Encrypt password using bcrypt
        const hashedPassword = await bcrypt.hash(user.password, 10);
        user.password = hashedPassword;
        return next();
    } catch (err) {
        return next(err);
    }
});

userSchema.methods.comparePassword = async function(candidatePassword) {
    const user = this;
    try {
        // Decrypt password using bcrypt and compare with candidate password
        const isMatch = await bcrypt.compare(candidatePassword, user.password);
        return isMatch;
    } catch (err) {
        return false;
    }
};

const User = mongoose.model('User', userSchema);

module.exports = User;