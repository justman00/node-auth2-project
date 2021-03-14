const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Users = require("../users/users-model");
const { jwtSecret } = require("../secrets/index"); // use this secret!
/*
    If the user does not provide a token in the Authorization header:
    status 401
    {
      "message": "Token required"
    }

    If the provided token does not verify:
    status 401
    {
      "message": "Token invalid"
    }

    Put the decoded token in the req object, to make life easier for middlewares downstream!
  */
const restricted = async (req, res, next) => {
  try {
    const token = req.headers.authorization;

    if (!token) {
      res.status(401).json({ message: "Token required." });
    } else {
      jwt.verify(token, jwtSecret, (err, decoded) => {
        if (err) {
          return res.status(401).json({ message: "Token invalid" });
        }
        console.log(decoded);
        req.decoded = decoded;
        next();
      });
    }
  } catch (err) {
    next(err);
  }
};
/*
    If the user does not provide a token in the Authorization header with a role_name
    inside its payload matching the role_name passed to this function as its argument:
    status 403
    {
      "message": "This is not for you"
    }

    Pull the decoded token from the req object, to avoid verifying it again!
  */
const only = (role_name) => async (req, res, next) => {
  try {
    const token = req.headers.authorization;

    console.log("role", req.decoded.role_name);
    if (!token || req.decoded.role_name !== role_name) {
      return res.status(403).json({ message: "This is not for you." });
    } else {
      next();
    }
  } catch (err) {
    next(err);
  }
};
/*
    If the username in req.body does NOT exist in the database
    status 401
    {
      "message": "Invalid credentials"
    }
  */
const checkUsernameExists = async (req, res, next) => {
  const { username, password } = req.body;

  Users.findBy(username)
    .then((user) => {
      const passwordValid = bcrypt.compare(password, user.password);
      if (!user || !passwordValid) {
        return res.status(401).json({ message: "Invalid credentials." });
      } else {
        req.user = user;
        next();
      }
    })
    .catch((err) => {
      next(err);
    });
};
/*
    If the role_name in the body is valid, set req.role_name to be the trimmed string and proceed.

    If role_name is missing from req.body, or if after trimming it is just an empty string,
    set req.role_name to be 'student' and allow the request to proceed.

    If role_name is 'admin' after trimming the string:
    status 422
    {
      "message": "Role name can not be admin"
    }

    If role_name is over 32 characters after trimming the string:
    status 422
    {
      "message": "Role name can not be longer than 32 chars"
    }
  */
const validateRoleName = async (req, res, next) => {
  try {
    const { role_name } = req.body;
    if (role_name) {
      req.roleName = role_name.trim();
      next();
    } else if (!role_name || req.roleName === "") {
      req.roleName = "student";
      next();
    } else if (req.roleName === "admin") {
      return res.status(422).json({ message: "Role name can not be admin" });
    } else if (req.roleName.length > 32) {
      return res
        .status(422)
        .json({ message: "Role name can not be longer than 32 chars" });
    } else {
      next();
    }
  } catch (err) {
    next(err);
  }
};

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
};
