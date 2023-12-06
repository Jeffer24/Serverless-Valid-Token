"use strict";
const jwt = require("jwt-simple");
const moment = require("moment");

const SECRET_KEY = "fgdffGWERWE4453453678978SDFRsdg";

module.exports.hello = async (event, context, callback) => {
  let validate = "allow";
  if (!event.headers.authorizationToken || !event.headers.modulo) {
    validate = "unauthorized";
  } else {
    var token = event.headers.authorizationToken;
    var modulo = event.headers.modulo;

    const newToken = token.replace(/['"]+/g, "");
    try {
      var payload = jwt.decode(newToken, SECRET_KEY);
      //console.log(payload)

      if (!payload || payload.exp <= moment.unix()) {
        validate = "1";
      } else {
        var modules = payload.modules;
        var check = false;
        modules.forEach((element) => {
          if (element.codModulo == modulo) {
            check = true;
            return;
          }
        });

        if (!check) {
          validate = "unauthorized";
        }
      }
    } catch (ex) {
      validate = "2";
    }
  }

  switch (validate) {
    case "allow":
      callback(null, generatePolicy("user", "Allow", event.methodArn));
      break;
    case "deny":
      callback(null, generatePolicy("user", "Deny", event.methodArn));
      break;
    case "unauthorized":
      callback("Unauthorized"); // Return a 401 Unauthorized response
      break;
    default:
      callback("Error: Invalid token"); // Return a 500 Invalid token response
  }
};

// Help function to generate an IAM policy
var generatePolicy = function (principalId, effect, resource) {
  var authResponse = {};

  authResponse.principalId = principalId;
  if (effect && resource) {
    var policyDocument = {};
    policyDocument.Version = "2012-10-17";
    policyDocument.Statement = [];
    var statementOne = {};
    statementOne.Action = "execute-api:Invoke";
    statementOne.Effect = effect;
    statementOne.Resource = resource;
    policyDocument.Statement[0] = statementOne;
    authResponse.policyDocument = policyDocument;
  }

  // Optional output with custom properties of the String, Number or Boolean type.
  authResponse.context = {
    stringKey: "stringval",
    booleanKey: true,
  };
  return authResponse;
};
