const router = require("express").Router();
const User = require("../users/users-model");
const { checkUsernameExists, validateRoleName } = require("./auth-middleware");
const jwt = require("jsonwebtoken");

// validateRoleName,
router.post("/register", validateRoleName, async (req, res, next) => {
  console.log(req.body);
  User.add({ ...req.body, role_name: req.role_name })
    .then((newUser) => {
      res.status(200).json(newUser);
    })
    .catch(next);

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
});

router.post("/login", checkUsernameExists, (req, res, next) => {
  const UserAuth = req.body;

  const token = jwt.sign(
    {
      username: UserAuth.username,
      user_role: UserAuth.role_name,
    },
    process.env.JWT_SECRET
  );
  res.cookies = token;
  res.cookie("token", token);
  res.status(200).json({ message: "sue is back!", token: token });

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
});

module.exports = router;
