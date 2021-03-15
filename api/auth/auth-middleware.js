const User = require("../users/users-model");
const jwt = require("jsonwebtoken");

const restricted = (req, res, next) => {
  const token = req.cookies.token;

  if (!token) {
    return res.status(200).json({ message: "Token required" });
  } else {
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
      if (err) {
        return res.status(200).json({ message: "Token invalid" });
      }
      req.decoded = decoded;
      console.log("A venit = == = = = =", decoded);
      next();
    });
  }

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
};

const only = (role_name) => async (req, res, next) => {
  console.log("Decoded", req.decoded.user_role);
  console.log("Compare", role_name);
  if (req.decoded.user_role === role_name) {
    next();
  } else {
    res.status(403).json({
      message: "This is not for you",
    });
  }
  /*
    If the user does not provide a token in the Authorization header with a role_name
    inside its payload matching the role_name passed to this function as its argument:
    status 403
    {
      "message": "This is not for you"
    }

    Pull the decoded token from the req object, to avoid verifying it again!
  */
};

const checkUsernameExists = (req, res, next) => {
  try {
    if (!User.findBy({ username: req.body.username })) {
      return res.status(401).json({ message: "Invalid credentials" });
    }
  } catch (error) {
    return res.status(401).json({ message: "Ops error !!! " });
  }

  /*
    If the username in req.body does NOT exist in the database
    status 401
    {
  y    "message": "Invalid credentials"
    }
  */
  next();
};

const validateRoleName = (req, res, next) => {
  if (req.body.role_name) {
    req.role_name = req.body.role_name.trim();

    if (req.role_name === "admin") {
      return res.status(422).json({ message: "Role name can not be admin" });
    }

    if (req.role_name.length > 32) {
      return res
        .status(422)
        .json({ message: "Role name can not be longer than 32 chars" });
    }

    next();
  } else {
    req.role_name = "student";
    next();
  }

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
};

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
};
