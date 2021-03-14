const router = require("express").Router();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Users = require("../users/users-model");
const { checkUsernameExists, validateRoleName } = require("./auth-middleware");
const { jwtSecret } = require("../secrets/index"); // use this secret!

/**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */

router.post("/register", validateRoleName, (req, res, next) => {
  const { username, password, role_name } = req.body;

  Users.add({
    username,
    password: bcrypt.hash(password, 20),
    role_name,
  })
    .then((newUser) => {
      res.status(201).json({ newUser: newUser });
    })
    .catch((err) => {
      next(err);
    });
});

/**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
router.post("/login", checkUsernameExists, async (req, res, next) => {
  try {
    const token = jwt.sign(
      {
        subject: req.user.id,
        username: req.user.username,
        role_name: req.user.role_name,
      },
      jwtSecret,
      {
        expiresIn: "24h",
      }
    );
    res.cookie("chocolatechipCookie", token);
    res.status(200).json({
      message: `${req.user.username} is back!!`,
      token: token,
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
