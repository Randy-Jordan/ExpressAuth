const express = require('express');
const cookieParser = require('cookie-parser');
const path = require('path')
const pool = require('./db')

require('dotenv').config()


const PORT = process.env.PORT
const cookieSecret = process.env.COOKIE_SECRET
const app = express();

app.use(cookieParser(cookieSecret));
app.use(express.urlencoded({extended: true }))
app.use(express.json({extended:false}))
app.use(express.static(path.join(__dirname,'public')))



app.use('/', require('./routes'))


app.listen(PORT, ()=> console.log('Server Running'))