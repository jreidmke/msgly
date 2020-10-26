//So here, we're going to need to import some pckgs and middleware.

const express = require("express");
const router = new express.Router();
const expressError = require("../expressError");
const db = require("../db");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { BCRYPT_WORK_FACTOR, SECRET_KEY } = require("../config");
const { ensureLoggedIn, ensureCorrectUser, authenticateJWT } = require("../middleware/auth");
const ExpressError = require("../expressError");

//whoa! That's was a lot of importing! OK. Now, let's look at some routing.

/** POST /login - login: {username, password} => {token}
 *
 * Make sure to update their last-login!
 *
 **/

router.post("/login", async(req, res, next) => {
    const { username, password } = req.body;
    if(!username || !password) {
        throw new ExpressError("Username and Password required!", 400);
    }
    const result = await db.query(`
    SELECT username, password
    FROM users
    WHERE username = $1
    `, [username]);
    const user = result.rows[0];
    if(user) {
        if(await bcrypt.compare(password, user.password)) {

            await db.query(`
            UPDATE users
            SET last_login_at=${Date.now()}
            WHERE username=$1
            `, [username]);

            const token = jwt.sign({ username }, SECRET_KEY);
            return res.json({ token });
        }
    }
    throw new ExpressError("Invalid Username or Password. Try again", 400);
})

/** POST /register - register user: registers, logs in, and returns token.
 *
 * {username, password, first_name, last_name, phone} => {token}.
 *
 *  Make sure to update their last-login!
 */
router.post("/register", async(req, res, next) => {
    try {
        const { username, password, first_name, last_name, phone } = req.body;
        if(!username || !password) {
            throw new ExpressError("Username and password required", 400);
        }
        let token = jwt.sign({username}, SECRET_KEY);
        const hashword = await bcrypt.hash(password, BCRYPT_WORK_FACTOR);
        const result = await db.query(`
        INSERT INTO users (username, password, first_name, last_name, phone, join_at, last_login_at)
        VALUES($1, $2, $3, $4, $5, current_timestamp, current_timestamp) RETURNING username
        `, [username, password, first_name, last_name, phone]);
        return res.json({token});
    } catch (error) {
        if (error.code === '23505') {
            return next(new ExpressError("Username taken. Please pick another!", 400));
          }
          return next(error)
    }
});


module.exports = router;
