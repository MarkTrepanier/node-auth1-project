// Require `checkUsernameFree`, `checkUsernameExists` and `checkPasswordLength`
// middleware functions from `auth-middleware.js`. You will need them here!
const User = require("../users/users-model");
const {
  checkUsernameExists,
  checkUsernameFree,
  checkPasswordLength,
} = require("./auth-middleware");

const router = require("express").Router();
const bcrypt = require("bcryptjs");

router.post(
  "/register",
  checkUsernameFree,
  checkPasswordLength,
  async (req, res, next) => {
    try {
      const { username, password } = req.body;
      const hashed = bcrypt.hashSync(password, 6);
      const newUser = { username, password: hashed };
      const posted = await User.add(newUser);
      res.status(201).json(posted);
    } catch (err) {
      next(err);
    }
  }
);

router.post("/login", checkUsernameExists, async (req, res, next) => {
  try {
    const { password } = req.body;

    const passwordValidation = bcrypt.compareSync(password, req.user.password);
    if (!passwordValidation) {
      return next({ status: 401, message: "invalid credentials" });
    }
    req.session.user = req.user;
    res.json({ message: `welcome ${req.user.username}` });
  } catch (err) {
    next(err);
  }
});

router.get("/logout", (req, res, next) => {
  if (!req.session.user) {
    return res.status(200).json({ message: "no session" });
  }
  req.session.destroy((err) => {
    if (err) {
      next();
    }
    res.status(200).json({ message: "logged out" });
  });
});
/**
  3 [GET] /api/auth/logout

  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }

  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }
 */

// Don't forget to add the router to the `exports` object so it can be required in other modules
module.exports = router;
