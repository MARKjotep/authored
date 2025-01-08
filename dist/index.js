// @bun
var D=(t)=>{return!isNaN(parseFloat(t))&&isFinite(t)};var M=(t)=>Array.isArray(t),m=(t)=>typeof t==="object";var U=(t)=>{return Number.isInteger(Number(t))};var T=()=>{let t=process.env.SECRET_KEY;if(!t)throw new Error("'SECRET_KEY' not found in .env file");return t};var Nt=new RegExp(/(\d+)(\d*)/,"m"),j=(t)=>Array.from({length:t},(i,n)=>n);var Ft=j(10).join("");var w=(t)=>{return Buffer.from(t)},H=(...t)=>{let i=new Bun.CryptoHasher("sha256",T());return t.forEach((n)=>{i.update(n)}),i.digest()},h=(t)=>JSON.stringify(t),Y=(t)=>{return JSON.parse(t)};var z=new TextDecoder,N=(t)=>{return z.decode(t)};class b extends Map{obj(t){t&&c(t).forEach(([i,n])=>this.set(i,n))}map(t){t.forEach((i,n)=>{if(m(i))this.ass(n,i);else this.set(n,i)})}ass(t,i){if(!this.has(t))this.set(t,{});G(this.get(t),i)}lacks(t){return!this.has(t)}init(t,i){return this.has(t)?this.get(t):this.set(t,i).get(t)}}var{entries:c,hasOwn:Mt}=Object;var G=Object.assign,P=(t)=>{return Object.keys(t).length};var V=["charset","name","property","http-equiv"],k=(t,i)=>{i.forEach((n)=>{for(let s of V)if(s in n){let e=n[s];t[`${s}_${s==="charset"?"":e}`]=n}})},a=(t,i)=>{i.forEach((n)=>{if("href"in n){let s=n.href;t[`${s}`]=n}})};class ${_head;constructor(t){this._head=new b(t)}set head(t){c(t).forEach(([i,n])=>{if(i==="title"||i==="base"){this._head.set(i,n);return}if(!M(n))return;switch(i){case"meta":return k(this._head.init("meta",{}),n);case"link":return a(this._head.init("link",{}),n);case"script":this._head.init(i,[]),this._head.get(i).push(...n);return}})}get head(){return this._head}}class v{htmlHead=new b;head;constructor(){this.head=(t={})=>{let i=new $(this.htmlHead);i.head=t,this.htmlHead=i.head}}}var X=(t,i="",{maxAge:n,expires:s,path:e,domain:o,secure:f,httpOnly:u,sameSite:E})=>{if(n instanceof Date)n=n.getSeconds();if(s instanceof Date)s=s.toUTCString();else if(s===0)s=new Date().toUTCString();return[["Domain",o],["Expires",s],["Max-Age",n],["Secure",f],["HttpOnly",u],["Path",e],["SameSite",E]].reduce((r,[C,O])=>{if(O!==void 0)r.push(`${C}=${O}`);return r},[`${t}=${i}`]).join("; ")};var tt=(t,i=!1)=>{if(D(t))return[+t,U(t)?"int":"float"];if(i&&/\.\w+$/.test(t))return[t,"file"];if(t==="/")return[t,"-"];if(t.length===36&&t.match(/\-/g)?.length===4)return[t,"uuid"];return[t,"string"]},it=(t)=>{let i=t.startsWith("/")?t:"/"+t,n=i.match(/(?<=\/)[^/].*?(?=\/|$)/g)??["/"],[s,e]=n.reduce(([o,f],u)=>{if(u.includes("<")){let E=u.match(/(?<=<)[^/].*?(?=>|$)/g);if(E?.length){let[g,r]=E[0].split(":");if(g&&r)o.push(g),f.push(r)}}else o.push(u===">"?"/":u);return[o,f]},[[],[]]);if(i.endsWith("/")&&i.length>1)s.push("/");return{parsed:s,args:e}};var nt=["int","float","file","uuid","string"];class st{_storage=new b;set(t){let{parsed:i,path:n}=t,s=h(i);if(!this._storage.get(s))this._storage.set(s,t);else throw`path: ${n} already used.`}get(t){let{parsed:i}=it(t),n={},s=this._storage.get(h(i));if(!s)for(let e of this._storage.keys()){let o=[],f=Y(e);if(i.length===f.length){let u=f.map((r,C)=>{let O=tt(i[C],i.length-1===C);if(r===O[0])return O[0];if(nt.includes(O[1]))return o.push(O[0]),O[1];return r}),E=h(u);if(this._storage.has(E)){s=this._storage.get(E),s.args.forEach((r,C)=>{n[r]=o[C]});break}}}return[s,n]}}class I{date;constructor(t){this.date=t?new Date(t):new Date}delta(t=null,i=!1){let n=I.delta(this.date.getTime(),t);return i?new Date(n):n}timed(t){if(!t)return this.date;return[["year","FullYear"],["month","Month"],["day","Date"],["hour","Hours"],["minute","Minutes"],["second","Seconds"]].reduce((n,[s,e])=>{let o=t[s];return o?new Date(n[`set${e}`](n[`get${e}`]()+o)):n},new Date(this.date))}static delta(t,i=null){return i?i-t:t-Date.now()}static get now(){return Date.now()}}class y{data;modified;new=!0;length=0;constructor(t={}){if(this.modified=!0,this.data={},this.length=P(t),this.length)this.new=!1;G(this.data,t)}set(t,i,n){if(!this.readonly&&t.data[i]!=n){if(this.modified=!0,!(i in t.data))this.length++;return t.data[i]=n,!0}return!1}get(t,i){if(i in t)return t[i];return t.data[i]}has(t,i){if(i in t.data)return!0;return!1}deleteProperty(t,i){if(!this.readonly&&i in t.data)this.modified=!0,delete t.data[i],this.length--;return!0}}class S extends y{sid;modified;readOnly;constructor(t="",i={},n=!1){super(i);this.sid=t;this.modified=!1,this.readOnly=n}get session(){return new Proxy(this,this)}}class R extends _{config;constructor(t,i){super(i??"salty");this.config=t}async openSession(t,i){if(t&&this.signer.unsign(t))return await this.fetchSession(t,i);return this.new}async fetchSession(t,i){return this.new}async saveSession(t,i,n=!1){return}get new(){return new S(this.generate(),{}).session}get readonly(){return new S(this.generate(),{},!0).session}get getExpiration(){let t=new Date,i=this.config.LIFETIME;return t.setDate(t.getDate()+i).toString()}setCookie(t,i,n=""){let s=null,e={};if(this.config.COOKIE_SAMESITE)s=this.config.COOKIE_SAMESITE;if(n)s=n;if(i===0)e.maxAge=i.toString();else e.expires=i;return X(this.config.COOKIE_NAME,t.sid,{domain:"",path:this.config.COOKIE_PATH,httpOnly:this.config.COOKIE_HTTPONLY,secure:this.config.COOKIE_SECURE,sameSite:s,...e})}async loadHeader(t,i){let n=async(e)=>{let o="";if(e)o=e.split(";").reduce((E,g)=>{let[r,C]=g.trim().split(/=(.*)/s);return E[r]=C,E},{}).session;let f=o;return await this.openSession(f,i)},s=t.headers;if(s){if("get"in s)return await n(s.get("cookie"));else if("cookie"in s)return await n(s.cookie)}return this.new}}import{randomBytes as et}from"crypto";var{CryptoHasher:ot}=globalThis.Bun;class B{salt;constructor(t){this.salt=t}getSignature(t){let i=this.deriveKey().toString();return H(i,t).toString("base64")}deriveKey(){return H(this.salt)}sign(t){let i=this.getSignature(t),n=w(t+"."+i);return N(n)}unsign(t){if(!(t.indexOf(".")>-1))throw Error("No sep found");let i=t.indexOf("."),n=t.slice(0,i),s=t.slice(i+1);return this.verifySignature(n,s)}loadUnsign(t){if(this.unsign(t)){let i=w(t),n=w(".").toString()[0];if(!(n in i))throw Error("No sep found");let s=i.indexOf(n),e=i.subarray(0,s);return Buffer.from(e.toString(),"base64").toString("utf-8")}}verifySignature(t,i){return this.getSignature(t)==i?!0:!1}}class _{signer;constructor(t){this.signer=new B(t)}generate(t=21){let n=et(t).toString("base64");if(n.endsWith("="))n=n.slice(0,-1);return this.signer.sign(n)}}function F(t){let i=new ot("md5");return i.update(t),i.digest("hex")}var{file:Z,gunzipSync:ft,gzipSync:ut,write:Et}=globalThis.Bun;import{promises as St}from"fs";import{mkdirSync as Ai,writeFileSync as rt}from"fs";var K=(t,i="")=>{try{return rt(t,i,{flag:"wx"}),!0}catch(n){return!1}};class J{path;data;constructor(t){this.data=new Map,this.path=t+"/"}async init(t){let i=F(t),n=this.path+i,s=Z(n);if(await s.exists()){let e=await s.arrayBuffer();try{let o=JSON.parse(N(ft(e)));return o.f_timed=Date.now(),this.data.set(i,o),o}catch(o){}}return null}async checkLast(t){let i=new Date(t);if(i.setMinutes(i.getMinutes()+60),i.getTime()<Date.now())return!0;return!1}async get(t){if(t){let i=this.data.get(t);if(i==null)return await this.init(t);else{if(i&&"f_timed"in i){if(await this.checkLast(i.f_timed))return await this.init(t)}return i}}return null}async set(t,i){let n=F(t),s=this.path+n;K(s,""),await Et(s,ut(JSON.stringify(i))),i.f_timed=Date.now(),this.data.set(t,i)}async delete(t){let i=F(t);this.data.delete(i);let n=this.path+i;Z(n).exists().then(async(s)=>{await St.unlink(n)}).catch()}}class L extends S{}class d extends R{isJWT;cacher;side=L;constructor(t,i=".sessions",n=!1){super(t);this.isJWT=n;this.cacher=new J(i)}life(t,i){let{LIFETIME:n,JWT_LIFETIME:s}=this.config;if(new I(i).timed({day:this.isJWT?s:n}).getTime()-new Date().getTime()>0)return!0;else return this.cacher.delete(t),!1}async fetchSession(t,i){let n=this.config.KEY_PREFIX+t,s=await this.cacher.get(n),e={};if(s){let o=!0;if("life"in s)o=this.life(n,s.life);e=o?JSON.parse(s.data):{}}return new this.side(t,e,i).session}async saveSession(t,i,n=!1){let s=(o)=>{if(i){let f=this.setCookie(t,o);if(i)i.set("Set-Cookie",f)}},e=this.config.KEY_PREFIX+t.sid;if(!t.length){if(!t.new&&(t.modified||n))this.cacher.delete(e),s(0);return}if(t.new&&t.modified){let o=new I().timed({day:this.config.LIFETIME}),f=JSON.stringify(t.data);await this.cacher.set(e,{data:f,life:I.now}),s(o)}return}}class x{client;query;f_timed;data;key;constructor(t,i,n){this.query=n,this.key=i,this.f_timed=Date.now(),this.data=new Map,this.client=t}async init(t){let i=await this.client.query({text:this.query+` where ${this.key} = $1`,values:[t]});for(let[n,s]of this.data)if(!s)this.data.delete(n);if(i.rowCount){let n=i.rows[0];return n.f_timed=Date.now(),this.data.set(t,n),n}else return this.data.set(t,null),null}async checkLast(t){let i=new Date(t);if(i.setMinutes(i.getMinutes()+15),i.getTime()<Date.now())return!0;return!1}async get(t){if(t){let i=this.data.get(t);if(i==null)return await this.init(t);else{if(i&&"f_timed"in i){if(await this.checkLast(i.f_timed))return await this.init(t)}return i}}return null}async set(t){if(this.key in t)t.f_timed=Date.now(),this.data.set(t[this.key],t)}async delete(t){this.data.delete(t)}}class W extends S{}class A extends R{sclass=W;client;pgc;constructor(t,i){super(i);this.client=t,this.pgc=new x(t,"sid","SELECT * FROM session")}async fetchSession(t){let i=this.config.KEY_PREFIX+t,n=await this.pgc.get(i),s={};if(n)s=JSON.parse(n.data);return new this.sclass(t,s).session}async saveSession(t,i,n,s=""){let e=this.config.KEY_PREFIX+t.sid;if(!Object.entries(t.data).length){if(t.modified||n){if(i){await this.client.query({text:"DELETE FROM session WHERE sid = $1",values:[e]}),await this.pgc.delete(e);let u=this.setCookie(t,0);i.header={"Set-Cookie":u}}}return}let o=new I().timed({day:this.config.LIFETIME}),f=JSON.stringify(t.data);if(i){let u=this.getExpiration;await this.client.query({text:"INSERT INTO session(sid, data, expiration) VALUES($1, $2, $3)",values:[e,f,u?u:null]}),await this.pgc.set({sid:e,data:f,expiration:u??"",life:I.now});let E=this.setCookie(t,o);i.header={"Set-Cookie":E}}}}var{CryptoHasher:gt}=globalThis.Bun;import{sign as Q,verify as It}from"jsonwebtoken";import{randomBytes as Ct}from"crypto";class l extends _{salt;constructor(){super("salty_jwt");this.salt="salty_jwt"}sign(t){let i={issuer:this.salt};return Q({data:t},T(),i)}get random(){let t={issuer:this.salt},i={data:Ot()};return Q(i,T(),t)}jwt(){let t=this.generate();return new S(t).session}verify(t,i){try{let n=It(t,T());if(n){let{data:s,iat:e,iss:o}=n;if(o==this.salt)if(i){let{days:f,hours:u,minutes:E,seconds:g}=i,r=new Date(e*1000);if(f)r=new Date(r.setDate(r.getDate()+f));else if(u)r=new Date(r.setHours(r.getHours()+u));else if(E)r=new Date(r.setMinutes(r.getMinutes()+E));else if(g)r=new Date(r.setSeconds(r.getSeconds()+g));if(r.getTime()-Date.now()>0)return s}else return s}}catch(n){}return null}open(t,i){if(t){let n=this.verify(t,i);if(n)return new S(t,n,!0).session}return this.jwt()}save(t){let i=t.data;if("access_token"in i)delete i.access_token;return this.sign(i)}new(t){return this.sign(t)}}function Ot(t=64){return new gt("sha256").update(Ct(t)).digest("hex")}class Tt{postgresClient;config={COOKIE_NAME:"session",COOKIE_DOMAIN:"127.0.0.1",COOKIE_PATH:"/",COOKIE_HTTPONLY:!0,COOKIE_SECURE:!0,REFRESH_EACH_REQUEST:!1,COOKIE_SAMESITE:"Strict",KEY_PREFIX:"session:",PERMANENT:!0,USE_SIGNER:!1,ID_LENGTH:32,FILE_THRESHOLD:500,LIFETIME:31,MAX_COOKIE_SIZE:4093,INTERFACE:"fs",STORAGE:".sessions",JWT_STORAGE:".jwt",JWT_LIFETIME:5};constructor({type:t="fs",dir:i}={}){t&&(this.config.INTERFACE=t),i&&this.initStorage(i)}initStorage(t){return this.config.STORAGE=t+"/"+this.config.STORAGE,this.config.JWT_STORAGE=t+"/"+this.config.JWT_STORAGE,this}get session(){if(this.config.INTERFACE==="postgres"&&this.postgresClient)return new A(this.postgresClient,this.config);return new d(this.config,this.config.STORAGE)}get jwt(){return new d(this.config,this.config.JWT_STORAGE)}}export{_ as sidGenerator,F as decodeSID,B as Signator,S as ServerSide,W as PostgreSession,A as PGInterface,x as PGCache,l as JWTSession,L as FSession,d as FSInterface,J as FSCached,R as AuthInterface,Tt as Auth};
