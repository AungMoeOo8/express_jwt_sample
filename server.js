const express = require("express");
const app = express();

const authRouter = require("./auth");
// const { authMiddleware } = require("./auth");

app.use(express.json());

app.use("/auth", authRouter);

const authMiddleware = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    res.json({ error: "Require authorization header" });
    return;
  }

  const token = authHeader.split(" ")[1];

  next();
};

app.get("/api", authMiddleware, (req, res) => res.json("middleware"));

app.listen(5000, () => console.log("Server listening at port:5000"));
