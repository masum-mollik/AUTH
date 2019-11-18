const router = require("express").Router();
const User = require("../model/User");
const { registerValidation } = require("../validation");
const bcrypt = require("bcryptjs");
//VALIDATION

router.post("/register", async (req, res) => {
	//VALIDATE THE DATA
	const { error } = registerValidation(req.body);
	if (error) return res.status(400).send(error.details[0].message);

	//unique user
	const emailExist = await User.findOne({ email: req.body.email });
	if (emailExist) return res.status(400).send("Email already exists");

	//HashPass
	const salt = await bcrypt.genSalt(10);
	const hashedPassword = await bcrypt.hash(req.body.password, salt);

	//Create a New User
	const user = new User({
		name: req.body.name,
		email: req.body.email,
		phone: req.body.phone,
		password: hashedPassword
	});
	try {
		const savedUser = await user.save();
		res.send({ user: user._id });
	} catch (err) {
		res.status(400).send(err);
	}
});

module.exports = router;
