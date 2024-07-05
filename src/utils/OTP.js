
// Utility function to generate a random character from a given string
function getRandomChar(charSet) {
  return charSet[Math.floor(Math.random() * charSet.length)];
}

// Function to generate a 6-digit alphanumeric OTP    
function generateOTP() {
    const alphanumericChars =
        "0123456789";
    let otp = "";
    for (let i = 0; i < 6; i++) {
        otp += getRandomChar(alphanumericChars);
    }
    return otp;
}


module.exports = {generateOTP }