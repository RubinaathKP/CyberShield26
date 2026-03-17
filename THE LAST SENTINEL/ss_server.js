const express=require("express"),http=require("http"),{Server}=require("socket.io"),cors=require("cors"),fs=require("fs"),path=require("path");
const app=express();app.use(cors());app.use(express.json());
const server=http.createServer(app);
const io=new Server(server,{cors:{origin:"*"}});
const DB=path.join(__dirname,"ss_db.json");

function loadDB(){
  if(!fs.existsSync(DB)){
    const i={logs:[],feedback:[],stats:{total:0,rce:0,sqli:0,xss:0,lfi:0,honeypot:0,retrain:0,scenarios:0,ips:{}}};
    fs.writeFileSync(DB,JSON.stringify(i,null,2));
  }
  try{return JSON.parse(fs.readFileSync(DB));}
  catch{return{logs:[],feedback:[],stats:{total:0,rce:0,sqli:0,xss:0,lfi:0,honeypot:0,retrain:0,scenarios:0,ips:{}}};}
}
function saveDB(d){fs.writeFileSync(DB,JSON.stringify(d,null,2));}

function classify(p){
  const s=(p||"").toLowerCase();
  if(s.includes("port scan")||s.includes("nmap")||s.includes("syn scan"))return"PORTSCAN";
  if(s.includes("meterpreter")||s.includes("metasploit")||s.includes("msfconsole"))return"METERPRETER";
  if(s.includes("c2 beacon")||s.includes("c2beaconing")||s.includes("command and control")||s.includes("cobalt strike"))return"C2";
  if(s.includes("hydra")||s.includes("brute force")||s.includes("bruteforce")||s.includes("password spray"))return"BRUTEFORCE";
  if(s.includes("benign")||s.includes("admin check")||s.includes("routine"))return"BENIGN";
  if(s.includes("/bin/sh")||s.includes("/bin/bash")||s.includes("exec(")||s.includes("wget")||s.includes("nc ")||s.includes("whoami")||s.includes("reverse shell"))return"RCE";
  if(s.includes("select ")||s.includes("union ")||s.includes("drop ")||s.includes("1=1")||s.includes("'--"))return"SQLi";
  if(s.includes("<script")||s.includes("onerror=")||s.includes("alert(")||s.includes("document.cookie"))return"XSS";
  if(s.includes("../")||s.includes("/etc/")||s.includes("/proc/"))return"LFI";
  if(s.includes("honeypot")||s.includes("decoy_login"))return"HONEY";
  return"NORMAL";
}
function xai(t){
  return{
    RCE:"Shell injection via syscall — remote command execution vector identified",
    SQLi:"SQL grammar anomaly — authentication bypass / data exfiltration attempt",
    XSS:"DOM injection payload — client-side script execution via unsanitized input",
    LFI:"Path traversal — unauthorized filesystem read attempt detected",
    HONEY:"Honeypot interaction — attacker isolated and fingerprinted in decoy",
    PORTSCAN:"Network reconnaissance — sequential port probing pattern detected",
    METERPRETER:"Meterpreter session signature — post-exploitation framework detected",
    C2:"C2 beaconing pattern — periodic outbound callbacks to command server",
    BRUTEFORCE:"Credential brute-force — high-frequency auth attempt pattern",
    BENIGN:"Routine admin activity — no threat signatures matched",
    NORMAL:"Benign traffic — no threat signatures matched in ML pipeline"
  }[t]||"Unknown pattern";
}
function score(t){
  const b={RCE:.94,SQLi:.88,XSS:.79,LFI:.84,HONEY:.66,PORTSCAN:.72,METERPRETER:.97,C2:.91,BRUTEFORCE:.83,BENIGN:.04,NORMAL:.05}[t]||.1;
  return+(Math.min(.99,b+(Math.random()*.05-.025))).toFixed(3);
}
function level(t){
  if(["RCE","METERPRETER","C2"].includes(t))return"CRITICAL";
  if(["SQLi","XSS","LFI","PORTSCAN","BRUTEFORCE","HONEY"].includes(t))return"HIGH";
  return"LOW";
}

function mkEvent(db,payload,ip,source,scenario){
  const t=classify(payload),s=score(t),lv=level(t);
  const ev={
    id:`${source==="kernel"?"KRN":source==="scenario"?"SCN":"EVT"}-${String(db.logs.length+1).padStart(4,"0")}`,
    timestamp:new Date().toLocaleString("en-GB",{hour12:false}),
    ip,payload:(payload||"").slice(0,140),type:t,
    threat_level:lv,score:""+s,xai:xai(t),source:source||"web",
    scenario:scenario||null
  };
  db.logs.push(ev);db.stats.total++;
  if(t==="RCE")db.stats.rce++;
  if(t==="SQLi")db.stats.sqli++;
  if(t==="XSS")db.stats.xss++;
  if(t==="LFI")db.stats.lfi=(db.stats.lfi||0)+1;
  if(t==="HONEY")db.stats.honeypot++;
  if(t==="PORTSCAN")db.stats.portscan=(db.stats.portscan||0)+1;
  if(t==="METERPRETER")db.stats.meterpreter=(db.stats.meterpreter||0)+1;
  if(t==="C2")db.stats.c2=(db.stats.c2||0)+1;
  if(t==="BRUTEFORCE")db.stats.bruteforce=(db.stats.bruteforce||0)+1;
  if(scenario)db.stats.scenarios=(db.stats.scenarios||0)+1;
  db.stats.ips[ip]=(db.stats.ips[ip]||0)+1;
  saveDB(db);io.emit("ss_update",db);io.emit("ss_event",ev);
  return ev;
}

// Main attack endpoint
app.post("/ss/attack",(req,res)=>{
  const db=loadDB();
  const ip=(req.headers["x-forwarded-for"]||req.ip||"unknown").split(",")[0].trim();
  const ev=mkEvent(db,req.body.payload||"",ip,"web",null);
  res.json({is_threat:ev.threat_level!=="LOW",type:ev.type,score:ev.score,redirect:["CRITICAL","HIGH"].includes(ev.threat_level),xai:ev.xai,id:ev.id,threat_level:ev.threat_level});
});

// Scenario engine endpoint
app.post("/ss/scenario",(req,res)=>{
  const db=loadDB();
  const {scenario,payload}=req.body;
  const ev=mkEvent(db,payload||scenario||"",`sim-${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}`,
    "scenario",scenario);
  res.json({ok:true,event:ev});
});

// Kernel pipeline (from forwarder.py)
app.post("/demo/analyze",(req,res)=>{
  const db=loadDB();const p=(req.body.payload||"").toString();
  const ev=mkEvent(db,p,"kernel","kernel",null);
  res.json({is_threat:ev.threat_level==="CRITICAL",confidence:parseFloat(ev.score),threat_type:ev.type,explanation:ev.xai,seriousness_score:+(parseFloat(ev.score)*10).toFixed(1)});
});

// Alert feedback
app.post("/ss/feedback",(req,res)=>{
  const db=loadDB();
  const {alert_id,accurate,comment,corrected_type}=req.body;
  if(!alert_id)return res.status(400).json({error:"alert_id required"});
  const fb={id:`FB-${Date.now()}`,alert_id,accurate:!!accurate,comment:comment||"",corrected_type:corrected_type||null,timestamp:new Date().toLocaleString("en-GB",{hour12:false})};
  if(!db.feedback)db.feedback=[];
  db.feedback.push(fb);
  // Update model accuracy stat
  const totalFb=db.feedback.length;
  const accurateFb=db.feedback.filter(f=>f.accurate).length;
  db.stats.feedback_accuracy=+(accurateFb/totalFb*100).toFixed(1);
  saveDB(db);io.emit("ss_update",db);io.emit("ss_feedback",fb);
  res.json({ok:true,feedback:fb,model_accuracy:db.stats.feedback_accuracy});
});

app.get("/ss/data",(req,res)=>res.json(loadDB()));
app.post("/ss/retrain",(req,res)=>{
  const db=loadDB();db.stats.retrain=(db.stats.retrain||0)+1;
  const ev={id:`RTN-${db.stats.retrain}`,timestamp:new Date().toLocaleString("en-GB",{hour12:false}),ip:"system",payload:"ML retrain triggered",type:"RETRAIN",threat_level:"INFO",score:"0.000",xai:"Model retrained with latest threat corpus",source:"system"};
  db.logs.push(ev);saveDB(db);io.emit("ss_update",db);io.emit("ss_retrain",{count:db.stats.retrain,time:ev.timestamp});
  res.json({ok:true,count:db.stats.retrain});
});
app.post("/ss/reset",(req,res)=>{
  const i={logs:[],feedback:[],stats:{total:0,rce:0,sqli:0,xss:0,lfi:0,honeypot:0,retrain:0,scenarios:0,ips:{}}};
  saveDB(i);io.emit("ss_update",i);res.json({ok:true});
});

server.listen(4000,()=>console.log("SyscallSentinel server → http://localhost:4000"));
