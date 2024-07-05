const { expect } = require('chai');
const request = require('supertest');
const app = require('../app');
const User = require('../model/userModel');
const userController = require('../controllers/userController');

