const mongoose = require('mongoose');

const chatSchema = new mongoose.Schema({
    sender: { type: String, required: true }, // Email
    receiver: { type: String, default: 'global' }, // Email or 'global'
    message: { type: String, required: true },
    // Legacy fields cached for performance/display
    username: String,
    avatar: String,
    
    reactions: [{ type: String }], // emails
    
    timestamp: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Chat', chatSchema);
