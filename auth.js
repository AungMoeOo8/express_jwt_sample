const express = require("express");
const authRouter = express.Router();
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
require("dotenv").config();

let userId = 0;
let users = [];
let refreshTokens = [];
const saltRounds = 4;

const generateAccessToken = (payload) => {
  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: 60 });
};

const generateRefreshToken = (payload) => {
  return jwt.sign(payload, process.env.REFRESH_TOKEN_SECRET, {
    expiresIn: "1h",
  });
};

const generateBothToken = (id, username, email, role) => {
  const accessToken = generateAccessToken({
    id,
    username,
    email,
    role,
  });

  const refreshToken = generateRefreshToken({
    id,
    username,
    email,
    role,
  });

  return { accessToken, refreshToken };
};

//Route for register
authRouter.post("/register", (req, res) => {
  const { username, email, password, role } = req.body;

  //Check if user already exists
  if (users.find((user) => user.email === email) != undefined) {
    res.status(400).json({ error: "User already exists!" });
    return;
  }

  //Generate salt for hash
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

      const { accessToken, refreshToken } = generateBothToken(
        userId,
        username,
        email,
        role
      );

      refreshTokens.push(refreshToken);

      res.status(201).json({ accessToken, refreshToken });
    });
  });
});

//Route for login
authRouter.post("/login", (req, res) => {
  const { email, password } = req.body;

  //Find user data from array or database
  const user = users.find((currentUser) => currentUser.email === email);

  //if array or database does not have provided email
  if (user === undefined) {
    res.json({ message: "No such user found!" });
    return;
  }

  bcrypt.compare(password, user.password, (error, result) => {
    if (error) {
      console.log(error);
      return;
    }

    //Switch between wrong password and token
    switch (result) {
      case false:
        res.json({ message: "Wrong Password!" });
        break;

      default:
        const { accessToken, refreshToken } = generateBothToken(
          user.id,
          user.username,
          user.email,
          user.role
        );

        refreshTokens.push(refreshToken);

        res.json({ accessToken, refreshToken });
        break;
    }
  });
});

//Route to get access token from refresh token
authRouter.post("/accessToken", (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) res.json({ error: "Request must include refresh token!" });

  const { id, usename, email, role } = jwt.decode(refreshToken);
  const accessToken = generateAccessToken({ id, usename, email, role });
  res.json({ accessToken });
});

module.exports = authRouter;
