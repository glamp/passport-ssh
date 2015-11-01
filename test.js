
var SSHStrategy = require("./").Strategy;



 var strategy = new SSHStrategy({}, function(username, worked){
  console.log(username)
 });

var req = {
  body: {
    username: "",
    password: ""
  },
  query: {
  }
};
var opts = {};

strategy.authenticate(req, opts)
