const jwt = require("jsonwebtoken");

/**
 * Generates a JSON Web Token (JWT).
 *
 * @param {Object} payload The data to be encoded in the JWT.
 * @param {string} secret The secret key used for signing the JWT.
 * @param {Object} options (optional) Additional options for the JWT, such as expiration time or algorithm.
 * @throws {Error} If there's an error during JWT generation.
 * @returns {string} The generated JWT string.
 */
function generateJWT(payload, secret, options = {}) {
    try {
        return jwt.sign(payload, secret, options);
    } catch (error) {
        throw new Error("Error generating JWT: " + error.message);
    }
}

/**
 * Verifies a JSON Web Token (JWT). 
 *
 * @param {string} token The JWT string to be verified.
 * @param {string} secret The secret key used for signing the JWT.
 * @returns {Object|null} The decoded payload if the JWT is valid, otherwise null.
 */
function verifyJWT(token, secret) {
    try {
        const decoded = jwt.verify(token, secret);

        // Check if the JWT has expired
        if (decoded.exp < Date.now() / 1000) {
        return null;
        }
        return decoded;
    } catch (error) {
        // Handle specific JWT verification errors 
        if (error.name === "JsonWebTokenError") {
        console.error("Invalid JWT:", error.message);
        } else if (error.name === "TokenExpiredError") {
        console.error("Expired JWT");
        } else {
        console.error("Unknown JWT verification error:", error.message);
        }
        return null;
    }
}

module.exports = {
    generateJWT,
    verifyJWT,
};
