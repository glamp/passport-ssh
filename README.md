# passport-ssh
Passport strategy for authenticating with the linux user group.


## Installation
```
$ npm install passport-ssh
```

## Usage
The ssh strategy authenticates users using [`ssh`](http://www.openssh.com/). You
can specify server credentials to attempt to ssh into. For example:

Basic setup using ssh daemon running on localhost:22
```
passport.use(new SSHStrategy());
```
if i tried to login as user `bob`, the equivalent ssh command would be: 
```
$ ssh bob@localhost
```

Example using custom hostname and port
```
passport.use(new SSHStrategy({
  host: "ec2-54-124-59-274.us-west-2.compute.amazonaws.com",
  port: 2200
}));
```
if i tried to login as user `ubuntu`, the equivalent ssh command would be: 
```
$ ssh -p 2200 ubuntu@ec2-54-124-59-274.us-west-2.compute.amazonaws.com
```

You can optionally provide a `verify` callback to handle custom edge cases
```
passport.use(new SSHStrategy(
  function(user, done) {
    done(null, user);
  }
));
```


## Authenticate Requests
Use passport.authenticate(), specifying the 'ssh' strategy, to authenticate 
requests.

```
app.get('/secret', passport.authenticate('ssh', { failureRedirect: '/login' }),
  function(req, res) {
    res.redriect("/");
  }
);
```

## Tests
nah
