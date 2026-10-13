'use strict';
const net=require('node:net');
const crypto=require('node:crypto');
const fs=require('node:fs');
const path=require('node:path');
const {WebSocket}=require('ws');
const KEY=fs.readFileSync(path.join(__dirname,'proofs','secret.txt'),'utf8').trim();
const TARGET=process.env.IB_WSS||'ws://127.0.0.1:8977/tunnel';
const PORT=Number(process.env.IB_SOCKS_PORT||1099);
const LOCAL_USER=process.env.IB_SOCKS_USER||'ib-pilot';
const LOCAL_PASSWORD=process.env.IB_SOCKS_PASSWORD||'ib-test-only-password-not-for-production';
function auth(){
 const id=process.env.IB_CLIENT_ID||'pilot-socks09',ts=Date.now(),nonce=crypto.randomBytes(16).toString('hex');
 const perDevice=crypto.createHmac('sha256',KEY).update('IB09-device:'+id).digest();
 const mac=crypto.createHmac('sha256',perDevice).update(id+'\n'+ts+'\n'+nonce).digest('hex');
 return {'x-ib-id':id,'x-ib-ts':String(ts),'x-ib-nonce':nonce,'x-ib-mac':mac};
}
function openBridge(destination,client,rest){
 const ws=new WebSocket(TARGET,{headers:auth(),perMessageDeflate:false,handshakeTimeout:9000});
 let ready=false,done=false;
 const finish=()=>{
  if(done)return;done=true;
  if(ws.readyState===ws.OPEN)ws.close();
  client.destroy();
 };
 function sendRest(data){if(data?.length&&ws.readyState===ws.OPEN)ws.send(data,{binary:true});}
 ws.on('open',()=>ws.send(JSON.stringify({op:'connect',host:destination.host,port:destination.port})));
 ws.on('message',(payload,binary)=>{
  if(binary){if(ready&&!done)client.write(payload);else finish();return;}
  let j;try{j=JSON.parse(String(payload));}catch(e){finish();return;}
  if(j.op==='connected'){
   ready=true;client.write(Buffer.from([5,0,0,1,0,0,0,0,0,0]));
   sendRest(rest);
  }else if(j.op==='end'){client.end();ws.close();}
  else if(j.op==='error'||j.op==='quota'){
   if(!ready)client.write(Buffer.from([5,1,0,1,0,0,0,0,0,0]));
   finish();
  }
 });
 ws.on('error',e=>{if(!ready)client.write(Buffer.from([5,1,0,1,0,0,0,0,0,0]));finish();});
 ws.on('close',()=>client.end());
 client.on('data',data=>{if(ready&&!done)sendRest(data);});
 client.on('close',()=>{if(ws.readyState===ws.OPEN)ws.close();});
}
const server=net.createServer(client=>{
 client.setTimeout(30000);client.on('timeout',()=>client.destroy());
 let buf=Buffer.alloc(0),phase='greet',method=0;
 const fail=()=>client.destroy();
 function drain(){
  while(true){
   if(phase==='greet'){
    if(buf.length<2)return;
    const n=buf[1];if(buf[0]!==5||n<1||n>8){fail();return;}
    if(buf.length<2+n)return;
    const methods=buf.subarray(2,2+n);
    method=methods.includes(2)?2:methods.includes(0)?0:255;
    client.write(Buffer.from([5,method]));buf=buf.subarray(2+n);
    if(method===255){fail();return;}phase=method===2?'auth':'request';continue;
   }
   if(phase==='auth'){
    if(buf.length<2)return;const n=buf[1];
    if(buf[0]!==1||n<1||n>100){fail();return;}
    if(buf.length<2+n+1)return;
    const pn=buf[2+n];if(pn<16||pn>255){fail();return;}
    if(buf.length<3+n+pn)return;
    const u=buf.subarray(2,2+n).toString(),p=buf.subarray(3+n,3+n+pn).toString();
    if(u!==LOCAL_USER||p!==LOCAL_PASSWORD){client.write(Buffer.from([1,1]));fail();return;}
    client.write(Buffer.from([1,0]));buf=buf.subarray(3+n+pn);phase='request';continue;
   }
   if(phase==='request'){
    if(buf.length<4)return;
    if(buf[0]!==5||buf[1]!==1||buf[2]!==0){client.write(Buffer.from([5,7,0,1,0,0,0,0,0,0]));fail();return;}
    const t=buf[3];let len=0,offset=4,host;
    if(t===1){len=4;}
    else if(t===3){if(buf.length<5)return;len=buf[4];offset=5;if(len<1||len>253){fail();return;}}
    else {client.write(Buffer.from([5,8,0,1,0,0,0,0,0,0]));fail();return;}
    if(buf.length<offset+len+2)return;
    if(t===1)host=Array.from(buf.subarray(offset,offset+len)).join('.');
    else host=buf.subarray(offset,offset+len).toString('utf8');
    const port=buf.readUInt16BE(offset+len);
    const rest=buf.subarray(offset+len+2);phase='relay';buf=Buffer.alloc(0);
    if(port!==80&&port!==443){client.write(Buffer.from([5,2,0,1,0,0,0,0,0,0]));fail();return;}
    openBridge({host,port},client,rest);
    return;
   }
   return;
  }
 }
 const read=data=>{if(phase==='relay'){client.off('data',read);return;}if(buf.length+data.length>65536){fail();return;}buf=Buffer.concat([buf,data]);drain();};
 client.on('data',read);
 client.on('error',()=>{});
});
server.listen(PORT,'127.0.0.1',()=>console.log('IB09_LOCAL_SOCKS_LISTENING port='+PORT));
