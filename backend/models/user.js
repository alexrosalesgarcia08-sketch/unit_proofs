// models/user.js

const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const config = require('../config/config').get(process.env.NODE_ENV);

const SALT_ROUNDS = 10;

const userSchema = new mongoose.Schema({
    email: {
        type: String,
        required: true,
        trim: true,
        lowercase: true,
        unique: true
    },
    password: {
        type: String,
        required: true,
        minlength: 6
    },
    firstname: {
        type: String,
        trim: true,
        maxlength: 100
    },
    lastname: {
        type: String,
        trim: true,
        maxlength: 100
    },
    token: {
        type: String
    }
});

// Hash the password before saving (only if it was modified)
userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) return next();

    try {
        this.password = await bcrypt.hash(this.password, SALT_ROUNDS);
        next();
    } catch (err) {
        next(err);
    }
});

// Compare passwords on login -> returns Promise<boolean>
userSchema.methods.comparePassword = function (candidatePassword) {
    return bcrypt.compare(candidatePassword, this.password);
};

// Generate JWT on login -> returns Promise<User>
userSchema.methods.generateToken = async function () {
    this.token = jwt.sign({ id: this._id.toHexString() }, config.SECRET, {
        expiresIn: '1d'
    });
    return this.save();
};

// Find a user by token -> returns Promise<User|null>
userSchema.statics.findByToken = async function (token) {
    const decoded = jwt.verify(token, config.SECRET); // throws if invalid/expired
    return this.findOne({ _id: decoded.id, token });
};

// Remove the token on logout -> returns Promise
userSchema.methods.deleteToken = function () {
    return this.updateOne({ $unset: { token: 1 } });
};

// Never expose password or token in JSON responses
userSchema.methods.toJSON = function () {
    const obj = this.toObject();
    delete obj.password;
    delete obj.token;
    return obj;
};

module.exports = mongoose.model('User', userSchema);