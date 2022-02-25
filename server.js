const express = require("express");
const app = express();

const authRouter = require('./auth')

app.use(express.json());

app.use('/auth', authRouter)

app.listen(5000, () => console.log("Server listening at port:5000"));
