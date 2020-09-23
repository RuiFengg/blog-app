const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { UserInputError } = require("apollo-server");

const {
  validateRegisterInput,
  validateLoginInput,
} = require("../../util/validators");
const { SECRET_KEY } = require("../../config");
const User = require("../../models/User");

module.exports = {
  Mutation: {
    async login(_, { username, password }) {
      checkUserLoginInput(username, password);

      const user = await User.findOne({ username });
      await checkLoginDetails(password, user);
      const token = generateToken(user);
      return {
        ...user._doc,
        id: user._id,
        token,
      };
    },
    async register(
      _,
      { registerInput: { username, email, password, confirmPassword } }
    ) {
      checkUserRegisterInput(username, email, password, confirmPassword);
      await checkDuplicateUsername(username);
      const newUser = await createUser(username, password, email);
      return newUser;
    },
  },
};

const checkUserRegisterInput = (username, email, password, confirmPassword) => {
  const { valid, errors } = validateRegisterInput(
    username,
    email,
    password,
    confirmPassword
  );
  if (!valid) {
    throw new UserInputError("Errors", { errors });
  }
};

const checkUserLoginInput = (username, password) => {
  const { valid, errors } = validateLoginInput(username, password);
  if (!valid) {
    throw new UserInputError("Errors", { errors });
  }
};

const checkDuplicateUsername = async (username) => {
  const isUserPresent = await User.findOne({ username });
  if (isUserPresent) {
    throw new UserInputError("Username is taken", {
      errors: {
        username: "This username is taken",
      },
    });
  }
};

const checkLoginDetails = async (password, user) => {
  if (!user) {
    throw new UserInputError("User not found", {
      errors: {
        general: "User not found",
      },
    });
  }
  const match = await bcrypt.compare(password, user.password);
  if (!match) {
    throw new UserInputError("Wrong credentials", {
      errors: {
        general: "Wrong credentials",
      },
    });
  }
};

const createUser = async (username, password, email) => {
  password = await bcrypt.hash(password, 12);
  const newUser = new User({
    email,
    username,
    password,
    createdAt: new Date().toISOString(),
  });

  const res = await newUser.save();

  const token = generateToken(res);

  return {
    ...res._doc,
    id: res._id,
    token,
  };
};

const generateToken = (user) => {
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
      username: user.username,
    },
    SECRET_KEY,
    { expiresIn: "1h" }
  );
};
