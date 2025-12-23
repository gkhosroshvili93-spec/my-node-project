const mongoose = require('mongoose');

const storySchema = new mongoose.Schema({
    userId: { type: String, required: true }, // Email
    authorName: String,
    authorAvatar: String,
    
    image: String, // for photo story
    text: String, // for text story
    background: String, // for text story
    
    createdAt: { type: Date, default: Date.now, expires: 86400 } // Auto-delete after 24 hours (86400 seconds)
});

module.exports = mongoose.model('Story', storySchema);
