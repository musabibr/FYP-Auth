const cloudinary = require("cloudinary").v2;

cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
});

const deleteOldImg = async (public_id) => {
    // await cloudinary.uploader.destroy(public_id);
    await cloudinary.api.delete_resources([public_id], {
        type: "upload",
        resource_type: "image",})
}

module.exports = {cloudinary, deleteOldImg}; 