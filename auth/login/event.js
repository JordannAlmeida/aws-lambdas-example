const jwt = require('jsonwebtoken');
const SECRET_KEY = process.env['SECRET_KEY_JWT'];

const generateToken = link => {
    const userData = {}; // TODO: recovery username, expire time and another data comparebe from database
    const remainingSeconds = secondsUntilExpired(userData.dataCreation, userData.expiress)
    if (link === userData.link && remainingSeconds > 0) {
        const payload = {
            username: username,
            role: userData.role,
            exp: Math.floor(Date.now() / 1000) + remainingSeconds
        };
        const token = jwt.sign(payload, SECRET_KEY);
        return {
            "acess_token": token,
            "expiresIn": remainingSeconds
        };
    } else {
        throw new Error('Invalid credentials.');
    }
}

const secondsUntilExpired = (dateCreation, expiresInSeconds) => {
    const creationDate = typeof dateCreation === 'string' ? new Date(dateCreation) : dateCreation;
    const expiryDate = new Date(creationDate.getTime() + expiresInSeconds * 1000);
    const remainingSeconds = Math.max(Math.ceil((expiryDate - new Date()) / 1000), 0);
    return remainingSeconds;
}

module.exports.handler = async (event, context) => {
    console.log('Received event:', JSON.stringify(event, null, 2));
    const url = event.path; //TODO extact correct url
    try {
        const tokenData = generateToken(url);
        return {
            statusCode: 200,
            body: JSON.stringify({
                access_token: tokenData.acess_token,
                type: 'Bearer',
                expiresIn: tokenData.expiresIn
            })
        };
    } catch (err) {
        console.error("Error to generate token", err);
        return {
            statusCode: 400,
            body: JSON.stringify({ message: err.message })
        };
    }
}