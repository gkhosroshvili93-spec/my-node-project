const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    role: { type: String, default: 'user', enum: ['user', 'admin'] },
    avatar: { type: String, default: '/uploads/default.png' },
    coverPhoto: { type: String, default: '' },
    bio: { type: String, default: '' },
    
    // Security
    securityQuestion: { type: String },
    securityAnswer: { type: String },
    is2faSetup: { type: Boolean, default: false },
    twofaSecret: { type: String, default: '' },
    
    // Social Graph (Storing Emails for simplicity to match current architecture)
    friends: [{ type: String }], 
    friendRequestsSent: [{ type: String }],
    friendRequestsReceived: [{ type: String }],
    
    blocked: [{ type: String }], // Emails of blocked users
    
    createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('User', userSchema);
