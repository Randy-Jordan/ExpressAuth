const Pool = require("pg").Pool;
require('dotenv').config()

const DB_USER = process.env.DB_USER
const DB_PASS = process.env.DB_PASS
const DB_PORT = process.env.DB_PORT
const DB_DATABASE = process.env.DB_DATABASE
const DB_HOST = process.env.DB_HOST


const pool = new Pool({
    user: DB_USER,
    password: DB_PASS,
    host: DB_HOST,
    port: DB_PORT,
    database: DB_DATABASE,
    max: 10,
    connectionTimeoutMillis: 0,
    idleTimeoutMillis: 0

});

module.exports = pool;  