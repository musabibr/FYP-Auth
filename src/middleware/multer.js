const multer = require('multer');

const multerStorage = multer.diskStorage({
    filename: function (req, file, cb) {
        cb(null ,file.originalname)
    }
});

// const multerStorage = multer.memoryStorage();

const multerFilter = (req, file, cb) => {
    // Check if the file is an image by checking the mimetype of the file
    if (file.mimetype.startsWith('image')) {
        // If the file is an image, call the callback function with the arguments (null, true)
        cb(null, true);
    } else {
        // If the file is not an image, call the callback function with the arguments (new Error('Not an image! Please upload only images.'), false)
        cb(new Error('Not an image! Please upload only images.'), false);
    }
};

const upload = multer({
    storage: multerStorage,
    fileFilter: multerFilter
});

module.exports = upload