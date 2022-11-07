const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const connection = require("./database");
const User = connection.models.User;
const validPassword = require("../lib/passwordUtils").validPassword;

const customFields = {
  usernameField: "usname",
  passwordField: "pw",
};

const verifyCallback = (username, password, done) => {
  User.findOne({ username: username })
    .then((user) => {
      if (!user) {
        return cb(null, false);
      }

      //Funtion defined at bottom at app.js
      const isValid = validPassport(password, user.hash, user.salt);

      if (isValid) {
        return done(null, user);
      } else {
        return done(null, false);
      }
    })
    .catch((err) => {
      done(err);
    });
};

const strategy = new LocalStrategy(customFields, verifyCallback);

passport.use(strategy);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((userId, done) => {
  User.findById(userId)
    .then((user) => {
      done(null, user);
    })
    .catch((err) => done(err));
});
