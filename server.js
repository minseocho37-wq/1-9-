const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const bcrypt = require("bcryptjs");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const Database = require("better-sqlite3");

const app = express();
const PORT = process.env.PORT || 3000;
const BASE = __dirname;
const DATA = path.join(BASE, "data");
const UPLOADS = path.join(DATA, "uploads");
fs.mkdirSync(UPLOADS, {recursive:true});

const db = new Database(path.join(DATA, "school.db"));
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS users(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 username TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL,
 subject TEXT NOT NULL,
 role TEXT NOT NULL DEFAULT 'teacher'
);
CREATE TABLE IF NOT EXISTS notices(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 subject TEXT NOT NULL,
 title TEXT NOT NULL,
 content TEXT NOT NULL,
 file_name TEXT,
 stored_file TEXT,
 important INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL,
 author_id INTEGER NOT NULL
);
`);

const subjects = ["국어","영어","수학","사회","과학","한국사","미술"];
const count = db.prepare("SELECT COUNT(*) c FROM users").get().c;
if (!count) {
  const hash = bcrypt.hashSync("1234", 10);
  const insert = db.prepare("INSERT INTO users(username,password_hash,subject,role) VALUES(?,?,?,'teacher')");
  const tx = db.transaction(()=>subjects.forEach(s=>insert.run(s,hash,s)));
  tx();
  console.log("Demo accounts created: subject username / password 1234");
}

app.use(express.json({limit:"2mb"}));
app.use(express.urlencoded({extended:true}));
app.use(session({
 secret: process.env.SESSION_SECRET || "CHANGE_THIS_SECRET_BEFORE_DEPLOY",
 resave:false, saveUninitialized:false,
 store:new SQLiteStore({db:"sessions.sqlite",dir:DATA}),
 cookie:{httpOnly:true,sameSite:"lax",secure:false,maxAge:8*60*60*1000}
}));
app.use(express.static(path.join(BASE,"public")));

const upload = multer({
 storage: multer.diskStorage({
  destination: (_,__,cb)=>cb(null,UPLOADS),
  filename: (_,file,cb)=>cb(null,Date.now()+"-"+Math.random().toString(36).slice(2)+path.extname(file.originalname))
 }),
 limits:{fileSize:10*1024*1024}
});

function auth(req,res,next){
 if(!req.session.user) return res.status(401).json({error:"로그인이 필요합니다."});
 next();
}
function teacherOnly(req,res,next){
 if(!req.session.user || req.session.user.role!=="teacher") return res.status(403).json({error:"권한이 없습니다."});
 next();
}
function now(){return new Date().toISOString();}

app.get("/api/subjects",(req,res)=>res.json(subjects));

app.get("/api/notices",(req,res)=>{
 const subject = req.query.subject;
 let sql = "SELECT n.id,n.subject,n.title,n.content,n.file_name,n.important,n.created_at,n.updated_at,u.username author FROM notices n JOIN users u ON u.id=n.author_id";
 const params=[];
 if(subject && subjects.includes(subject)){sql+=" WHERE n.subject=?";params.push(subject)}
 sql+=" ORDER BY n.updated_at DESC";
 res.json(db.prepare(sql).all(...params));
});

app.get("/api/notices/:id",(req,res)=>{
 const n=db.prepare("SELECT n.*,u.username author FROM notices n JOIN users u ON u.id=n.author_id WHERE n.id=?").get(req.params.id);
 if(!n) return res.status(404).json({error:"공지 없음"});
 res.json(n);
});

app.get("/api/me",(req,res)=>res.json({user:req.session.user||null}));

app.post("/api/login",(req,res)=>{
 const {username,password}=req.body;
 const u=db.prepare("SELECT * FROM users WHERE username=?").get(username);
 if(!u || !bcrypt.compareSync(password||"",u.password_hash)) return res.status(401).json({error:"아이디 또는 비밀번호가 올바르지 않습니다."});
 req.session.user={id:u.id,username:u.username,subject:u.subject,role:u.role};
 res.json({user:req.session.user});
});
app.post("/api/logout",(req,res)=>req.session.destroy(()=>res.json({ok:true})));

app.post("/api/notices",teacherOnly,upload.single("file"),(req,res)=>{
 const {title,content,important}=req.body;
 if(!title?.trim() || !content?.trim()) return res.status(400).json({error:"제목과 내용을 입력하세요."});
 const t=now();
 const result=db.prepare(`INSERT INTO notices(subject,title,content,file_name,stored_file,important,created_at,updated_at,author_id)
 VALUES(?,?,?,?,?,?,?,?,?)`).run(req.session.user.subject,title.trim(),content.trim(),req.file?.originalname||null,req.file?.filename||null,important==="1"?1:0,t,t,req.session.user.id);
 broadcast({type:"notice_changed",id:result.lastInsertRowid});
 res.json({ok:true,id:result.lastInsertRowid});
});

app.put("/api/notices/:id",teacherOnly,upload.single("file"),(req,res)=>{
 const old=db.prepare("SELECT * FROM notices WHERE id=?").get(req.params.id);
 if(!old || old.author_id!==req.session.user.id) return res.status(404).json({error:"공지를 찾을 수 없습니다."});
 const {title,content,important}=req.body;
 if(!title?.trim() || !content?.trim()) return res.status(400).json({error:"제목과 내용을 입력하세요."});
 let stored=old.stored_file, fileName=old.file_name;
 if(req.file){stored=req.file.filename;fileName=req.file.originalname;if(old.stored_file) try{fs.unlinkSync(path.join(UPLOADS,old.stored_file))}catch{}}
 db.prepare(`UPDATE notices SET title=?,content=?,file_name=?,stored_file=?,important=?,updated_at=? WHERE id=?`)
 .run(title.trim(),content.trim(),fileName,stored,important==="1"?1:0,now(),old.id);
 broadcast({type:"notice_changed",id:old.id});
 res.json({ok:true});
});

app.delete("/api/notices/:id",teacherOnly,(req,res)=>{
 const old=db.prepare("SELECT * FROM notices WHERE id=?").get(req.params.id);
 if(!old || old.author_id!==req.session.user.id) return res.status(404).json({error:"공지를 찾을 수 없습니다."});
 db.prepare("DELETE FROM notices WHERE id=?").run(old.id);
 if(old.stored_file) try{fs.unlinkSync(path.join(UPLOADS,old.stored_file))}catch{}
 broadcast({type:"notice_changed",id:old.id});
 res.json({ok:true});
});

app.get("/api/files/:name",(req,res)=>{
 const safe=path.basename(req.params.name);
 const row=db.prepare("SELECT file_name FROM notices WHERE stored_file=?").get(safe);
 if(!row) return res.status(404).end();
 res.download(path.join(UPLOADS,safe),row.file_name);
});

// Simple Server-Sent Events for real-time updates.
const clients=new Set();
app.get("/api/events",(req,res)=>{
 res.setHeader("Content-Type","text/event-stream");
 res.setHeader("Cache-Control","no-cache");
 res.setHeader("Connection","keep-alive");
 res.flushHeaders();
 res.write(`data: ${JSON.stringify({type:"connected"})}\n\n`);
 clients.add(res);
 req.on("close",()=>clients.delete(res));
});
function broadcast(data){for(const res of clients) res.write(`data: ${JSON.stringify(data)}\n\n`);}

app.listen(PORT,()=>console.log(`School notice server: http://localhost:${PORT}`));
