require('dotenv').config();
const mongoose = require('mongoose');

// uri
const { MONGODB_URL_DEV } = process.env

const connectToDatabase = async () => {
    try {
        await mongoose.connect(MONGODB_URL_DEV, {
            // useNewUrlParser: true,
            // useUnifiedTopology: true
        });
        console.log('MongoDB connected');
    } catch (err) {
        console.log(err.message);
        process.exit(1);
    }
}
connectToDatabase();
