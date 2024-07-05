require('dotenv').config();
const mongoose = require('mongoose');

// uri
const  MONGODB_URL  = (process.env.NODE_ENV === 'production') ? process.env.MONGODB_URL_PROD : process.env.MONGODB_URL_DEV;

const connectToDatabase = async () => {
    try {
        await mongoose.connect(MONGODB_URL, {
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
