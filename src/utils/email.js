const nodemailer = require('nodemailer');
const pug = require('pug');
const {convert} = require('html-to-text');

module.exports = class Email {
  constructor(user, url) {
    this.to = user.email;
    this.firstName = user.name?.split(" ")[0];
    this.url = url;
    this.from = `Psychotherapist <${process.env.EMAIL_FROM}>`;
  }

  newTransport() {
    if (process.env.NODE_ENV === "production") {
      return nodemailer.createTransport({
        host: process.env.EMAIL_HOST,
        port: process.env.EMAIL_PORT,
        secure: false,
        auth: {
          user: process.env.EMAIL_USERNAME,
          pass: process.env.EMAIL_PASSWORD,
        },
      });
    }
  }

  // Send the actual email
  async send(template, subject, other = "") {
    // 1) Render HTML based on a pug template
    const html = pug.renderFile(`${__dirname}/../views/email/${template}.pug`, {
      firstName: this.firstName,
      url: this.url,
      code: other,
      subject,
    });

    // 2) Define email options
    const mailOptions = {
      from: this.from,
      to: this.to,
      subject,
      html,
      text: convert(html, { wordwrap: 130 }),
    };

    // 3) Create a transport and send email
    await this.newTransport().sendMail(mailOptions);
  }
  async sendOtp(code) {
    try {
      await this.send("otp", "Welcome to the Psychotherapist Family!",code);

    } catch (error) {
      console.log(error);
    }
  }

  async sendWelcome() {
    try {
      await this.send("welcome", "Welcome to the Psychotherapist Family!");
      
    } catch (error) {
      console.log(error);
    }
  }

  async sendPasswordReset() {
    await this.send(
      "passwordReset",
      "Your password reset token (valid for only 10 minutes)"
    );
  }
};
