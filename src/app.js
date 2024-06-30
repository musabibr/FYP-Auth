require('./config/db');
const express = require('express');
const bodyParser = express;
const cors = require('cors');


// creating the server
const app = express();
app.use(cors());
app.use(bodyParser());

module.exports = app