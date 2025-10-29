import dotenv from "dotenv";
dotenv.config();
import express from "express";
import cors from "cors";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { Sequelize, DataTypes } from "sequelize";


const app = express();
app.use(
  cors({
    origin: [
      "https://92355.github.io",          // ✅ GitHub Pages 도메인
      "https://oojinwoo-front.onrender.com", // (혹시 Vercel이나 Render Front도 쓴다면 추가)
    ],
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    credentials: true,
  })
);
app.use(express.json());

const sequelize = new Sequelize(
  process.env.MYSQLDATABASE || "railway",
  process.env.MYSQLUSER || "root",
  process.env.MYSQLPASSWORD || "pw",
  {
    host: process.env.MYSQLHOST || "localhost",
    dialect: "mysql",
    port: process.env.MYSQLPORT || 3306,
  }
);

// const sequelize = new Sequelize("mini_platform", "root", "pw", {
//   host: "localhost",
//   dialect: "mysql",
// });

const User = sequelize.define("User", {
  username: { type: DataTypes.STRING, unique: true, allowNull: false },
  password: { type: DataTypes.STRING, allowNull: false },
  name: { type: DataTypes.STRING, allowNull: false },
  role: {                    
    type: DataTypes.ENUM("user", "admin"),
    defaultValue: "user",
  },
});

await sequelize.sync({ alter: true });

const Post = sequelize.define("Post", {
  title: { type: DataTypes.STRING, allowNull: false },
  content: { type: DataTypes.TEXT, allowNull: false },
});

User.hasMany(Post, { foreignKey: "userId", onDelete: "CASCADE" });
Post.belongsTo(User, { foreignKey: "userId" });

await sequelize.sync({ alter: true });

const SECRET = "mySecret";
//댓글기능
const Comment = sequelize.define("Comment", {
  content: { type: DataTypes.TEXT, allowNull: false },
});


//댓글 1
// 관계 설정
User.hasMany(Comment, { foreignKey: "userId", onDelete: "CASCADE" });
Post.hasMany(Comment, { foreignKey: "postId", onDelete: "CASCADE" });
Comment.belongsTo(User, { foreignKey: "userId" });
Comment.belongsTo(Post, { foreignKey: "postId" });

await sequelize.sync({ alter: true });
//

function auth(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "로그인이 필요합니다." });
  try {
    const decoded = jwt.verify(token, SECRET);
    req.user = decoded; // ✅ { id, role } 저장
    next();
  } catch {
    res.status(403).json({ error: "토큰이 유효하지 않습니다." });
  }
}


// ✅ 회원가입
app.post("/api/register", async (req, res) => {
  const { username, password, name } = req.body;
  const hash = await bcrypt.hash(password, 10);
  await User.create({ username, password: hash, name });
  res.json({ message: "회원가입 성공" });
});

// ✅ 로그인
// ✅ 로그인
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ where: { username } });
  if (!user) return res.status(401).json({ error: "존재하지 않는 사용자입니다." });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(401).json({ error: "비밀번호가 틀립니다." });

  // ✅ role 포함
  const token = jwt.sign(
    { id: user.id, role: user.role },
    SECRET,
    { expiresIn: "7d" }
  );

  res.json({ token, user });
});


// ✅ 내 프로필
app.get("/api/profile", auth, async (req, res) => {
  const user = await User.findByPk(req.user.id, {
    attributes: ["id", "username", "name", "createdAt"],
  });
  res.json(user);
});

// ✅ 회원탈퇴
app.delete("/api/profile", auth, async (req, res) => {
  await User.destroy({ where: { id: req.user.id } });
  res.json({ message: "회원탈퇴 완료" });
});

// ✅ 게시글 작성
app.post("/api/posts", auth, async (req, res) => {
  const post = await Post.create({
    title: req.body.title,
    content: req.body.content,
    userId: req.user.id,
  });
  res.json(post);
});

////////////////
// ✅ 댓글 작성
app.post("/api/posts/:id/comments", auth, async (req, res) => {
  const { content } = req.body;
  const postId = req.params.id;
  const comment = await Comment.create({
    content,
    userId: req.user.id,
    postId,
  });
  res.json(comment);
});

// ✅ 댓글 목록 불러오기
app.get("/api/posts/:id/comments", async (req, res) => {
  const postId = req.params.id;
  const comments = await Comment.findAll({
    where: { postId },
    include: [{ model: User, attributes: ["name"] }],
    order: [["id", "ASC"]],
  });
  res.json(comments);
});

// ✅ 댓글 삭제
app.delete("/api/comments/:id", auth, async (req, res) => {
  const comment = await Comment.findByPk(req.params.id);
  if (!comment) return res.status(404).json({ error: "댓글 없음" });

  // ✅ 관리자 or 본인만 가능
  if (req.user.role !== "admin" && comment.userId !== req.user.id)
    return res.status(403).json({ error: "삭제 권한 없음" });

  await comment.destroy();
  res.json({ message: "삭제 완료" });
});

// ✅ 댓글 수정
app.put("/api/comments/:id", auth, async (req, res) => {
  const comment = await Comment.findByPk(req.params.id);
  if (!comment) return res.status(404).json({ error: "댓글 없음" });

  // ✅ 관리자 or 본인만 가능
  if (req.user.role !== "admin" && comment.userId !== req.user.id)
    return res.status(403).json({ error: "수정 권한 없음" });

  comment.content = req.body.content;
  await comment.save();
  res.json(comment);
});
/////////////////
// ✅ 게시글 목록 (작성자 포함)
app.get("/api/posts", async (req, res) => {
  const posts = await Post.findAll({
    attributes: ["id", "title", "content", "userId", "createdAt"],
    include: [{ model: User, attributes: ["name"] }],
    order: [["id", "DESC"]],
  });
  res.json(posts);
});

// ✅ 특정 유저의 게시글 (내 게시글)
app.get("/api/myposts", auth, async (req, res) => {
  const posts = await Post.findAll({
    where: { userId: req.user.id },
    attributes: ["id", "title", "content", "createdAt"],
    order: [["id", "DESC"]],
  });
  res.json(posts);
});
// 게시글 단건 조회
app.get("/api/posts/:id", async (req, res) => {
  const post = await Post.findByPk(req.params.id, {
    include: [{ model: User, attributes: ["name"] }],
  });
  if (!post) return res.status(404).json({ error: "게시글 없음" });
  res.json(post);
});
// ✅ 내 댓글 목록
app.get("/api/mycomments", auth, async (req, res) => {
  const comments = await Comment.findAll({
    where: { userId: req.user.id },
    include: [
      { model: Post, attributes: ["title", "id"] },
      { model: User, attributes: ["name"] },
    ],
    order: [["id", "DESC"]],
  });
  res.json(comments);
});




// ✅ 게시글 수정

app.put("/api/posts/:id", auth, async (req, res) => {
  const post = await Post.findByPk(req.params.id);
  if (!post) return res.status(404).json({ error: "게시글 없음" });

  // ✅ 관리자 or 본인만 가능
  if (req.user.role !== "admin" && post.userId !== req.user.id)
    return res.status(403).json({ error: "수정 권한이 없습니다." });

  post.title = req.body.title;
  post.content = req.body.content;
  await post.save();
  res.json(post);
});


// ✅ 게시글 삭제
app.delete("/api/posts/:id", auth, async (req, res) => {
  const post = await Post.findByPk(req.params.id);
  if (!post) return res.status(404).json({ error: "게시글 없음" });

  // ✅ 관리자 or 본인만 가능
  if (req.user.role !== "admin" && post.userId !== req.user.id)
    return res.status(403).json({ error: "삭제 권한이 없습니다." });

  await post.destroy();
  res.json({ message: "삭제 완료" });
});


app.listen(4000, "0.0.0.0", () => {
  console.log("✅ 서버 외부 접근 허용: http://<내 IP>:4000");
});
