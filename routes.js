const express = require('express')
const path = require('path');
const router = express.Router();
const pool = require('./db')
const auth = require('./middleware/auth')
const crypto = require('crypto')
const bcrypt = require('bcrypt');

router.post("/signup", async (req, res) => {
    
    const {uname,email,pw} = req.body 
    try{
        // See if username or email already exists.
        const query = "SELECT * FROM public.users WHERE email = $1 OR WHERE uname = $2" 
        const queryResult = await pool.query(query,[email,uname]);
        
        // If username or email doesn't exist, sign up the user.
        if (queryResult.rowCount === 0){
            // Hash password, generate date, user id, session id.
            const hash =  await bcrypt.hash(pw, 10) // Pashword and hash-salt
            const date = new Date()
            const uid = crypto.randomBytes(24).toString('base64')
            const sid = crypto.randomBytes(24).toString('base64')
            const sql = "INSERT INTO public.users (email,uname,pw,uid,sid,llogin,jdate) VALUES ($1,$2,$3,$4,$5,$6,$7)"
            const values = [email,uname,hash,uid,sid,date,date]
            await pool.query(sql,values)
            // Success 
            res.redirect(302,'http://localhost:5000/signin')

        } else
            res.status(409).send("Email already exists..")
            
            

    } catch(error){
        res.status(500).send('Server Error')
    }
    
})

router.post('/signin',async (req,res)=>{
    const {email,pw} = req.body 

    try {
        // Validate email.
        const query = "SELECT * FROM public.users WHERE email = $1"
        const queryResult = await pool.query(query,[email]);

        // Invalid email.
        if (queryResult.rowCount === 0){
           res.status(400).send("Incorrect email or password")
        }
        // Email is valid, now validate the password.
        else{
            const saltedPassword = queryResult.rows[0].pw;
            const validationResult = await bcrypt.compare(pw, saltedPassword)

        // Validation success, user is logged in, update DB.
            if(validationResult === true){
                const sessionId =  crypto.randomBytes(24).toString('base64')
                const sql = "UPDATE public.users SET sid = $1 WHERE email = $2"
                await pool.query(sql,[sessionId,email]);
                
                res.cookie('id', sessionId, { maxAge: 9000000, httpOnly: true, signed:true,sameSite:'strict',path:'/' });
                res.redirect(301,'http://localhost:5000/private')
               
            // Invalid Login
            } else
                res.status(400).send("Incorrect email or password")
        }
        
    } catch (error) {
        res.status(500).send('Server Error') 
    }




})

router.post('/signout', async(req,res)=>{
    try {
        const sessionId = req.signedCookies.id;
        if (sessionId){
            // User signout remove cookie update sid
            const sql = "UPDATE public.users SET sid = null WHERE sid = $1"
            const result = await pool.query(sql,[sessionId]);
            res.clearCookie('id');
            res.status(200).send("Logged out successfully")
        }
    } catch (error) {
        res.status(500).send('Server Error')
    }
})

// Returns current users data
router.get('/@/me',auth, async(req,res)=>{
    try {    
        res.json(res.user)
    } catch (error) {
        res.status(500).send('Server Error')
    }
})

// Changes  current users data
router.post('/@/me',auth, async(req,res)=>{
    // See if the new email they've picked is taken
    try {
        const sql = "SELECT * FROM public.users WHERE email = $1"
        const result = await pool.query(sql,[req.body.email]);
        // If its taken
        if (result.rowCount != 0){
            res.status(409).send("Email is already taken.")
        }else{
            // See if they have a valid session id
            try {
                const sessionId = req.cookies.SESSION_ID;
                const sql = "UPDATE public.users SET email = $1 WHERE sid = $2"
                const result = await pool.query(sql,[req.body.email,sessionId]);
                if (result.rowCount === 0){ // They don't have a valid session id.
                    res.status(401).send('You are not authorized for this route');
                }else // Valid session id, email is not taken. 
                    res.status(200).send('Updated successfully')
            } catch (error) {
                res.status(500).send('Server Error')
            }

        }

    } catch (error) {
        res.status(500).send('Server Error')
    }
    
})
// Get public information of any user
router.get('/@/:uname',auth, async(req,res)=>{
    try { // See if the username exists
        sql = 'SELECT uname AS Username, jdate as JoinDate FROM public.users WHERE uname = $1'
        result = await pool.query(sql,[req.params.uname]);
        
        if(result.rowCount === 0){ // No user
            res.status(404).send("No users with that name.")
        }else
        res.status(200).json(result.rows[0])
    } catch (error) {
        res.status(500).send('Server Error')
    }
})

module.exports = router;