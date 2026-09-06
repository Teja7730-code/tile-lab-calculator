import { getStore } from '@netlify/blobs';
const STORE='ceramic-lab-data', KEY='database';
const ok=(x,s=200)=>new Response(JSON.stringify(x),{status:s,headers:{'content-type':'application/json'}});
const user=process.env.LAB_USERNAME||'admin', pass=process.env.LAB_PASSWORD||'1234';
const tokenFor=()=>Buffer.from(`${user}:${Date.now()}:ceramic-lab`).toString('base64');
const valid=t=>{try{return Buffer.from(t||'','base64').toString().startsWith(user+':')&&Buffer.from(t||'','base64').toString().endsWith(':ceramic-lab')}catch{return false}};
export default async req=>{
 if(req.method!=='POST')return ok({error:'POST required'},405);
 const b=await req.json().catch(()=>null); if(!b)return ok({error:'Invalid JSON'},400);
 if(b.action==='login') return b.username===user&&b.password===pass?ok({token:tokenFor()}):ok({error:'Invalid username or password'},401);
 if(!valid(b.token))return ok({error:'Not authenticated'},401);
 const store=getStore({name:STORE,consistency:'strong'});
 if(b.action==='get')return ok({data:await store.get(KEY,{type:'json',consistency:'strong'})});
 if(b.action==='save'){await store.setJSON(KEY,b.data);return ok({saved:true});}
 return ok({error:'Unknown action'},400);
};
