const mongoose = require('mongoose');

const newsSchema = new mongoose.Schema({
    title: { type: String, required: true },
    content: { type: String, required: true },
    author: String,
    date: { type: String } // Storing as string to match legacy format "DD.MM.YYYY" or Date object? Code used local string.
});

module.exports = mongoose.model('News', newsSchema);
