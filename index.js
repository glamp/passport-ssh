/**
 * Module dependencies.
 */
var passport = require('passport-strategy')
  , util = require('util')
  , sshClient = require('ssh2').Client;


/**
 * `Strategy` constructor.
 *
 * The local authentication strategy authenticates requests based on the
 * credentials submitted through an HTML-based login form.
 *
 * Applications must supply a `verify` callback which accepts `username` and
 * `password` credentials, and then calls the `done` callback supplying a
 * `user`, which should be set to `false` if the credentials are not valid.
 * If an exception occured, `err` should be set.
 *
 * Optionally, `options` can be used to change the fields in which the
 * credentials are found.
 *
 * Options:
 *   - `usernameField`  field name where the username is found, defaults to _username_
 *   - `passwordField`  field name where the password is found, defaults to _password_
 *   - `passReqToCallback`  when `true`, `req` is the first argument to the verify callback (default: `false`)
 *
 * Examples:
 *
 *     passport.use(new LocalStrategy(
 *       function(username, password, done) {
 *         User.findOne({ username: username, password: password }, function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  if (typeof options == 'function') {
    verify = options;
    options = {};
  }

  if (!verify) {
    throw new TypeError('LocalStrategy requires a verify callback');
  }
  
  // where we're going to be looking for the username/password in the req
  this._usernameField = options.usernameField || 'username';
  this._passwordField = options.passwordField || 'password';
  // ssh config
  this._host = options.host || "localhost";
  this._port = options.port || 22;
  
  passport.Strategy.call(this);
  this.name = 'local';
  this._verify = verify;
  this._passReqToCallback = options.passReqToCallback;
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

function ssh(host, port, username, password, fn) {
  var conn = new sshClient();
  conn.on('keyboard-interactive', function(name, instructions, instructionsLang, prompts, finish) {
    finish([password]);
  });

  conn.on('ready', function() {
    fn(null, true);
  }).connect({
    host: host,
    port: port,
    username: username,
    password: password,
    tryKeyboard: true
  });

  conn.on('error', function(err) {
    fn(null, false);
  });
}


/**
 * Authenticate request based on the contents of a form submission.
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function(req, options) {
  options = options || {};
  
  var username = req.body[this._usernameField] || req.query[this._usernameField];
  var password = req.body[this._passwordField] || req.query[this._passwordField];
  
  var self = this;


  if (!username || !password) {
    return new Error({ message: options.badRequestMessage || 'Missing credentials' }, 400);
  }

  ssh(this._host, this._port, username, password, function(err, isValid) {

    if (err) {
      return new Error(err);
    }
    if (isValid==false) {
      return new Error({ message: "Invalid credentials." });
    }

    function verified(err, user, info) {
      if (err) {
        return new Error(err);
      }
      if (!user) {
        return self.fail(info);
      }
      self.success(user, info);
    }

    if (this._passReqToCallback) {
      self._verify(req, username, verified);
    } else {
      self._verify(username, verified);
    }
  });
  
};


/**
 * Expose `Strategy`.
 */
exports.Strategy = Strategy;