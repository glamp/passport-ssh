/**
 * Module dependencies.
 */
var passport = require('passport-strategy')
  , util = require('util')
  , sshClient = require('ssh2').Client
  , userid = require('userid');


/**
 * `Strategy` constructor.
 *
 * The ssh strategy authenticates requests based on credentials specified
 * in an HTML-based login form (i.e. a form with "username" and "password"
 * fields).
 *
 * Applications can optionally specify a `verify` callback which accepts
 * `user` and then calls a `done` callback, supplying a `user`, which should
 * be set to `false` if something isn't right. If an exception occured, `err` 
 * should be set.
 *
 * Optionally, `options` can be used to change the fields in which the
 * credentials are found and/or update the ssh configuration.
 *
 * Options:
 *   - `usernameField`  field name where the username is found, defaults to _username_
 *   - `passwordField`  field name where the password is found, defaults to _password_
 *   - `host` hostname of the ssh server, defaults to _localhost_
 *   - `port` port ssh is running on `host`, defaults to _22_
 *   - `passReqToCallback`  when `true`, `req` is the first argument to the verify callback (default: `false`)
 *
 * Examples:
 *
 *     passport.use(new SSHStrategy());
 *
 *     passport.use(new SSHStrategy({
 *        host: process.env.SSH_HOST || "localhost"
 *     }));
 *
 *     passport.use(new SSHStrategy(
 *        function(user, done) {
 *          done(null, user);
 *        }
 *     ));
 *
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

  // where we're going to be looking for the username/password in the req
  this._usernameField = options.usernameField || 'username';
  this._passwordField = options.passwordField || 'password';
  // ssh config
  this._host = options.host || "localhost";
  this._port = options.port || 22;
  
  passport.Strategy.call(this);
  this.name = 'ssh';
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
    var user = {
      username: username,
      uid: userid.uid(username)
    }
    fn(null, user);
  }).connect({
    host: host,
    port: port,
    username: username,
    password: password,
    tryKeyboard: true
  });

  conn.on('error', function(err) {
    fn(null, null);
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
    return self.error(new Error(options.badRequestMessage || 'Missing credentials'));
  }

  ssh(this._host, this._port, username, password, function(err, user) {

    if (err) {
      return new Error(err);
    }


    function verified(err, user, info) {
      if (err) {
        return new Error(err);
      }
      if (!user) {
        return self.fail(info);
      }

      user.id = user.uid;
      self.success(user, info);
    }

    if (this._passReqToCallback) {
      if (self._verify) {
        self._verify(req, user, verified);
      } else {
        verified(null, req, user);
      }
    } else {
      if (self._verify) {
        self._verify(user, verified);
      } else {
        verified(null, user);
      }
    }
  });
  
};


/**
 * Expose `Strategy`.
 */
exports.Strategy = Strategy;
