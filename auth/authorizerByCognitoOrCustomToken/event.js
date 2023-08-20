const AWS = require('aws-sdk');
const jwt = require('jsonwebtoken');
const SECRET_KEY = process.env['SECRET_KEY_JWT'];

const cognito = new AWS.CognitoIdentityServiceProvider();

const checkUserCognito = async (authorizarion) => {
    try {
        const params = {
            AccessToken: authorizarion.split('Bearer ')[1]
        };
        const data = await cognito.getUser(params).promise();
        return data !== null && data !== undefined;
    } catch (err) {
        console.error("Unauthorized", err);
        return false; 
    }
}

const checkSelfTokenAutorization = (authorizarion) => {
    try {
        const payload = jwt.verify(authorizarion.split('Bearer ')[1], SECRET_KEY);
        return payload !== null && payload !== undefined;
    } catch (err) {
        console.error('Invalid token:', err);
        return false;
    }
}

const generatePolicy = (principalId, effect, resource) => {
    const authResponse = {};
    
    authResponse.principalId = principalId;
    if (effect && resource) {
        const policyDocument = {};
        policyDocument.Version = '2012-10-17'; 
        policyDocument.Statement = [];
        const statementOne = {};
        statementOne.Action = 'execute-api:Invoke'; 
        statementOne.Effect = effect;
        statementOne.Resource = resource;
        policyDocument.Statement[0] = statementOne;
        authResponse.policyDocument = policyDocument;
    }
    return authResponse;
  }

module.exports.handler = async (event, context, callback) => {
    console.log('Received event:', JSON.stringify(event, null, 2));
    const authorizarion = event.headers["Authorization"] || event.headers["authorization"];
    let permission = "Deny";
    if(authorizarion !== null && authorizarion !== undefined && authorizarion !== '') {
        if(await checkUserCognito(authorizarion)) {
            permission = "Allow";
        }
        else if(checkSelfTokenAutorization(authorizarion)) {
            permission = "Allow";
        }
    }
    callback(null, generatePolicy('user', permission, event.methodArn));
}