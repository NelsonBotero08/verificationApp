const {
  getAll,
  create,
  getOne,
  remove,
  update,
  getVerifyCode,
  login,
  getMe,
  resetPassword,
  updatePasswordUser,
} = require("../controllers/user.controllers");
const express = require("express");
const verifyJWT = require("../utils/verifyJWT");

const userRouter = express.Router();

userRouter.route("/users").get(verifyJWT, getAll).post(create);

userRouter.route("/users/login").post(login);

userRouter.route("/users/me").get(verifyJWT, getMe);

userRouter.route("/users/reset_password").post(resetPassword);

userRouter
  .route("/users/:id")
  .get(verifyJWT, getOne)
  .delete(verifyJWT, remove)
  .put(verifyJWT, update);

userRouter.route("/users/reset_password/:code").post(updatePasswordUser);

userRouter.route("/users/verify/:code").get(getVerifyCode);

module.exports = userRouter;
