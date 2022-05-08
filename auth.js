const express = require("express");
const authRouter = express.Router();
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
require("dotenv").config();

let userId = 0;
let users = [];
let refreshToken = [];
const saltRounds = 4;

const generateAccessToken = (payload) => {
  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: "20s" });
};

const generateRefreshToken = (payload) => {
  return jwt.sign(payload, process.env.REFRESH_TOKEN_SECRET);
};

//Route for register
authRouter.post("/register", (req, res) => {
  const { username, email, password, role } = req.body;

  bcrypt.genSalt(saltRounds, (error, salt) => {
    if (error) {
      res.json({ genSaltError: error });
      return;
    }

    bcrypt.hash(password, salt, (error, hash) => {
      if (error) {
        res.json({ hashError: error });
        return;
      }

      //Add user to array or database
      users.push({
        id: (userId += 1),
        username,
        email,
        password: hash,
        role,
      });

      const accessToken = generateAccessToken({
        id: userId,
        username: username,
        email: email,
        role: role,
      });

      const refreshToken = generateRefreshToken({
        id: userId,
        username: username,
        email: email,
        role: role,
      });

      res.json({ accessToken, refreshToken });
    });
  });
});

//Route for login
authRouter.post("/login", (req, res) => {
  const { email, password } = req.body;

  //Find user data from array or database
  const user = users.find((currentUser) => {
    return currentUser.email === email;
  });

  //if array or database does not have provided email
  if (user === undefined) {
    res.json({ message: "No such user found!" });
    return;
  }

  bcrypt.compare(password, user.password, (error, result) => {
    if (error) {
      console.log(error);
    }

    //Switch between wrong password and token
    switch (result) {
      case false:
        res.json({ message: "Wrong Password!" });
        break;

      default:
        const accessToken = generateAccessToken({
          id: user.id,
          username: user.username,
          email: user.email,
          role: user.role,
        });

        const refreshToken = generateRefreshToken({
          id: user.id,
          username: user.username,
          email: user.email,
          role: user.role,
        });

        res.json({ accessToken, refreshToken });
        break;
    }
  });
});

//Route to get access token from refresh token
authRouter.get("/token", (req, res) => {});

module.exports = authRouter;
