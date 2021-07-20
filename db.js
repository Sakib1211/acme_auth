const jwt = require("jsonwebtoken");
require("dotenv").config();
const bcrypt = require("bcrypt");

const Sequelize = require("sequelize");
const { STRING } = Sequelize;
const config = {
  logging: false,
};

if (process.env.LOGGING) {
  delete config.logging;
}
const conn = new Sequelize(
  process.env.DATABASE_URL || "postgres://localhost/acme_db",
  config
);

const User = conn.define("user", {
  username: STRING,
  password: STRING,
});

const Note = conn.define("note", {
  text: {
    type: Sequelize.STRING,
  },
});

User.addHook("beforeCreate", async (user) => {
  const salt = await bcrypt.genSalt(12);
  const hashedPassword = await bcrypt.hash(user.password, salt);
  user.password = hashedPassword;
});

User.byToken = async (token) => {
  try {
    const decoded = jwt.verify(token, process.env.JWT);
    const user = await User.findByPk(decoded.userId);
    if (user) {
      return user;
    }
    const error = Error("bad credentials");
    error.status = 401;
    throw error;
  } catch (ex) {
    const error = Error("bad credentials");
    error.status = 401;
    throw error;
  }
};

User.authenticate = async ({ username, password }) => {
  const user = await User.findOne({
    where: {
      username,
    },
  });
  const verifyPw = await bcrypt.compare(password, user.password);
  if (!verifyPw) {
    throw Error("Password is incorrect");
  } else {
    if (user) {
      let jwtToken = jwt.sign({ userId: user.id }, process.env.JWT, {
        expiresIn: "1d",
      });
      return jwtToken;
    }
    const error = Error("bad credentials");
    error.status = 401;
    throw error;
  }
};

const syncAndSeed = async () => {
  await conn.sync({ force: true });

  const notes = [
    { text: "finals were amazing :)" },
    { text: "I love food!" },
    { text: "cant wait for Friday" },
  ];
  const [note1, note2, note3] = await Promise.all(
    notes.map((note) => Note.create(note))
  );

  const credentials = [
    { username: "lucy", password: "lucy_pw" },
    { username: "moe", password: "moe_pw" },
    { username: "larry", password: "larry_pw" },
  ];
  const [lucy, moe, larry] = await Promise.all(
    credentials.map((credential) => User.create(credential))
  );
  await lucy.setNotes(note1);
  await larry.setNotes([note2, note3]);

  return {
    users: {
      lucy,
      moe,
      larry,
    },
  };
};

Note.belongsTo(User);
User.hasMany(Note);

module.exports = {
  syncAndSeed,
  models: {
    User,
    Note,
  },
};
