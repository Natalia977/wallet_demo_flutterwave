require("dotenv").config();
require("./config/database").connect();
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();

app.use(express.json());

//importing user context
const User = require("./model/user");

//register
app.post("/register", async (req, res) => {
    //register logic
    try {
        //get user input
        const { first_name, last_name, email, password } = req.body;

        //validate user input
        if (!(email && password && first_name && last_name)) {
            res.status(400).send("All input is required");
        }

        //check if user already exist
        //validate  if user exist  in our database
        const oldUser = await User.findOne({email});

        if (oldUser){
            return res.status(409).send("User already exist. Please login");
        }

        //encrypt user password
        encryptedPassword = await bcrypt.hash(password, 10);

        //create user in our database
        const user = await User.create({
            first_name,
            last_name,
            email: email.toLowerCase(),
            password: encryptedPassword,
        });

        //create token
        const token = jwt.sign(
            { user_id: user._id, email },
            process.env.TOKEN_KEY,
            { expiresIn: "2h"},
        );
        //save user token
        user.token = token;

        //return new user
        res.status(201).json(user);
    } catch (err) {
        console.log(err);
    }
});

//login
app.post("/login", async (req, res) => {
    //login logic
    try {
        //get user input    
        const { email, password } = req.body;

        //validate user input
        if (!(email && password)) {
            res.status(400).send("All input is required");
        }
        //validate if user exist in our DB
        const user = await User.findOne({email});

        if (user && (await bcrypt.compare(password, user.password))) {
            //create token
            const token = jwt.sign(
                { user_id: user._id, email },
                process.env.TOKEN_KEY,
                { expiresIn: "2h" }
            )
            //save user token 
            user.token = token;
            
            //user 
            res.status(200).json(user);
        };

        res.status(400).send("Invalid Credentials");
    } catch (err) {
        console.log(err);
    }
});

//logica

module.exports = app;