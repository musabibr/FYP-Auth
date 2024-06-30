require('dotenv').config()
const app = require('./app')

const { PORT } = process.env

const startServer = () => {
    try {
        app.listen(PORT, () => {
            console.log(`Server is listening on port ${PORT}`);
        })
    } catch (error) {
        console.log(error.message);
    }
}

startServer()