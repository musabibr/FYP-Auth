const bcrypt = require("bcrypt");
// const salt = bcrypt.genSalt();
const salt = process.env.SALT;

encryptData = async (data) => {
    return await bcrypt.hash(data, salt);
    };

compareData = async (storedData, userData) => {
        return await bcrypt.compare(`${storedData}`, `${userData}`);
    }


module.exports = {encryptData , compareData}