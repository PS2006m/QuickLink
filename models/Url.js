const mongoose = require('mongoose');

const urlSchema = new mongoose.Schema({
  shortId: { type: String, unique: true },
  originalUrl: {type :String ,required : true},
  userEmail: {type : String ,  required : true},
  clicks: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Url', urlSchema);
