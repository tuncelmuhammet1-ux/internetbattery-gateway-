import {createHash} from 'node:crypto';
const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
const MAX_FRAME = 256 * 1024;
const utf8 = new TextDecoder('utf-8', {fatal:true});

function closePayload(code, message='') {
  const text = Buffer.from(message, 'utf8').subarray(0, 110);
  const data=Buffer.alloc(2+text.length);data.writeUInt16BE(code);text.copy(data,2);return data;
}
function frame(opcode, body) {
  const p=Buffer.isBuffer(body)?body:Buffer.from(body);
  const n=p.length;let header;
  if(n<=125){header=Buffer.from([0x80|opcode,n]);}
  else if(n<=65535){header=Buffer.alloc(4);header[0]=0x80|opcode;header[1]=126;header.writeUInt16BE(n,2);}
  else {header=Buffer.alloc(10);header[0]=0x80|opcode;header[1]=127;header.writeBigUInt64BE(BigInt(n),2);}
  return Buffer.concat([header,p]);
}
export function upgradeWebSocket(req, socket, head, onMessage, onClose) {
  const key=req.headers['sec-websocket-key'];
  const valid = req.headers['upgrade']?.toLowerCase()==='websocket' &&
    req.headers['connection']?.toLowerCase().split(/\s*,\s*/).includes('upgrade') &&
    req.headers['sec-websocket-version']==='13' &&
    typeof key==='string' && /^[A-Za-z0-9+/]{22}==$/.test(key) && Buffer.from(key,'base64').length===16;
  if(!valid){socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n');return null;}
  const digest=createHash('sha1').update(key+GUID).digest('base64');
  socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: '+digest+'\r\n\r\n');
  let buffer=Buffer.alloc(0),closed=false;
  const session={
    sendJson(value){ if(closed)return false;const b=Buffer.from(JSON.stringify(value),'utf8');if(b.length>MAX_FRAME)return false;return socket.write(frame(1,b)); },
    sendBinary(value){ if(closed)return false;const b=Buffer.from(value);if(b.length>MAX_FRAME)return false;return socket.write(frame(2,b)); },
    onDrain(callback){if(!closed)socket.once('drain',callback);},
    close(code=1000,reason=''){ if(closed)return;closed=true;socket.write(frame(8,closePayload(code,reason)));socket.end();onClose?.(); },
    get closed(){return closed;}
  };
  function fail(code){session.close(code);}
  function parse(data){
    if(closed)return;
    if(data?.length){ buffer=Buffer.concat([buffer,data]);if(buffer.length>MAX_FRAME+32){fail(1009);return;} }
    while(buffer.length>=2 && !closed){
      const flags=buffer[0], fin=Boolean(flags&0x80), op=flags&0x0f, masked=Boolean(buffer[1]&0x80);
      if(!fin || flags&0x70 || !masked || ![1,2,8,9,10].includes(op)){fail(1002);return;}
      let len=buffer[1]&0x7f, off=2;
      if(len===126){if(buffer.length<4)return;len=buffer.readUInt16BE(2);off=4;}
      else if(len===127){if(buffer.length<10)return;const n=buffer.readBigUInt64BE(2);if(n>BigInt(MAX_FRAME)){fail(1009);return;}len=Number(n);off=10;}
      if(len>MAX_FRAME || ((op&0x8)!==0 && len>125)){fail(1009);return;}
      if(buffer.length<off+4+len)return;
      const mask=buffer.subarray(off,off+4),data=Buffer.from(buffer.subarray(off+4,off+4+len));
      buffer=buffer.subarray(off+4+len);
      for(let i=0;i<data.length;i++)data[i]^=mask[i&3];
      if(op===8){session.close();return;}
      if(op===9){socket.write(frame(10,data));continue;}
      if(op===10)continue;
      try {
        if(op===2)onMessage(data,session);
        else onMessage(JSON.parse(utf8.decode(data)),session);
      }catch(e){session.sendJson({t:'error',error:'invalid_json'});}
    }
  }
  socket.on('data',parse);
  socket.on('error',()=>session.close());
  socket.on('close',()=>{if(!closed){closed=true;onClose?.();}});
  if(head?.length)parse(head);
  return session;
}
