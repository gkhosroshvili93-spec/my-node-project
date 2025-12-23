const mongoose = require('mongoose');

const commentSchema = new mongoose.Schema({
    authorName: String,
    authorEmail: String,
    authorAvatar: String, // Snapshot of avatar at comment time? Or dynamic? legacy code stored it.
    text: String,
    timestamp: { type: Date, default: Date.now }
});

const postSchema = new mongoose.Schema({
    userId: { type: String, required: true }, // Email of author
    authorName: String,
    authorAvatar: String,
    content: String,
    image: String,
    feeling: String,
    feelingIcon: String,
    privacy: { type: String, default: 'public', enum: ['public', 'friends'] },
    
    likes: [{ type: String }], // Array of emails who liked
    comments: [commentSchema],
    
    timestamp: { type: Date, default: Date.now }
});

// Virtual to ensure .id works if we switch to _id, but we might just use _id
postSchema.set('toJSON', { virtuals: true });

module.exports = mongoose.model('Post', postSchema);
