const pool = require('../db')
const crypto = require('crypto')
require('dotenv').config()


module.exports = async function(req,res,next){
       
    try {
        const sessionId = req.signedCookies.id;
        const sql = "SELECT uname AS username, email, llogin AS lastlogin,jdate AS joindate FROM public.users WHERE sid = $1"
        const result = await pool.query(sql,[sessionId]);

            if (result.rowCount === 0){
                res.status(401).send('You are not authorized for this route');
            } else{
                res.user = result.rows[0]
                next()
            }
        
    } catch (error) {
        res.status(500).send('Server Error')
    }

        
}