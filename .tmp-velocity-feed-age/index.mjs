import fs from 'node:fs';
import crypto from 'node:crypto';

const PROGRAM = 'vELoC1audYbSYVRXn1vPaV8Axoa9oU6BYmNGZZBDZ1P';
const ORACLE = '2k3UHX6ehRFzx5fTVvbL6FwXhMjkucjJDL9MuVKLo8TV';
const EXPECTED_PROGRAM_DATA = 'HkRf36jvUB32dnHjHqpMnPcKJhUP2TUKJTH7RDTifJm7';
const EXPECTED_ELF = '1b7b06d17af813b5a505df8f534bfd0779a1a7457f0d2626b1a45c8741686c80';
const DEPLOYMENT_SLOT = 435978201;
const MAX_PAGES = Number(process.env.MAX_PAGES ?? 320);
const OUT = process.env.OUT_DIR ?? 'index';
const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const RPCS = [
  'https://solana-rpc.publicnode.com',
  'https://api.mainnet-beta.solana.com',
  'https://solana.drpc.org',
  'https://1rpc.io/solana',
  'https://mainnet-beta.solflare.network',
];
fs.mkdirSync(OUT,{recursive:true});
const sleep=(ms)=>new Promise((resolve)=>setTimeout(resolve,ms));
let cursor=0;

function b58encode(data){
  let number=BigInt('0x'+Buffer.from(data).toString('hex')), encoded='';
  while(number>0n){const remainder=Number(number%58n);number/=58n;encoded=ALPHABET[remainder]+encoded}
  let leading=0;for(const byte of data){if(byte!==0)break;leading++}
  return '1'.repeat(leading)+encoded;
}
async function raw(endpoint,method,params,timeoutMs=90000){
  const controller=new AbortController();const timer=setTimeout(()=>controller.abort(),timeoutMs);
  try{
    const response=await fetch(endpoint,{method:'POST',headers:{'content-type':'application/json','user-agent':'ZDB-feed-age-index/2'},body:JSON.stringify({jsonrpc:'2.0',id:1,method,params}),signal:controller.signal});
    const text=await response.text();
    if(!response.ok)throw new Error(`${endpoint} HTTP ${response.status}: ${text.slice(0,200)}`);
    const body=JSON.parse(text);if(body.error)throw new Error(`${endpoint} RPC ${JSON.stringify(body.error)}`);return body.result;
  }finally{clearTimeout(timer)}
}
async function rpc(method,params,attempts=15){
  let last;
  for(let attempt=0;attempt<attempts;attempt++){
    const endpoint=RPCS[(cursor+attempt)%RPCS.length];
    try{const result=await raw(endpoint,method,params);cursor=(RPCS.indexOf(endpoint)+1)%RPCS.length;return{endpoint,result}}
    catch(error){last=error;await sleep(Math.min(5000,150*(2**Math.min(attempt,5)))+Math.floor(Math.random()*100))}
  }
  throw last;
}
function canonicalElfSize(data){
  if(data.length<64||data.subarray(0,4).toString('hex')!=='7f454c46'||data[4]!==2||data[5]!==1)throw new Error('not ELF64 LE');
  const phoff=Number(data.readBigUInt64LE(0x20)),shoff=Number(data.readBigUInt64LE(0x28)),ehsize=data.readUInt16LE(0x34),phentsize=data.readUInt16LE(0x36),phnum=data.readUInt16LE(0x38),shentsize=data.readUInt16LE(0x3a),shnum=data.readUInt16LE(0x3c);
  let maximum=Math.max(64,ehsize);
  if(phoff&&phentsize&&phnum){maximum=Math.max(maximum,phoff+phentsize*phnum);for(let i=0;i<phnum;i++){const offset=phoff+i*phentsize;maximum=Math.max(maximum,Number(data.readBigUInt64LE(offset+8)+data.readBigUInt64LE(offset+32)))}}
  if(shoff&&shentsize&&shnum){maximum=Math.max(maximum,shoff+shentsize*shnum);for(let i=0;i<shnum;i++){const offset=shoff+i*shentsize;if(data.readUInt32LE(offset+4)!==8)maximum=Math.max(maximum,Number(data.readBigUInt64LE(offset+24)+data.readBigUInt64LE(offset+32)))}}
  if(maximum>data.length)throw new Error('ELF extent outside ProgramData');
  return maximum;
}

const programResponse=await rpc('getAccountInfo',[PROGRAM,{encoding:'base64',commitment:'finalized'}]);
const programRaw=Buffer.from(programResponse.result.value.data[0],'base64');
const programData=b58encode(programRaw.subarray(4,36));
const pdResponse=await rpc('getAccountInfo',[programData,{encoding:'base64',commitment:'finalized'}]);
const pdRaw=Buffer.from(pdResponse.result.value.data[0],'base64');
const deploymentSlot=Number(pdRaw.readBigUInt64LE(4));
const payload=pdRaw.subarray(45);
const canonical=payload.subarray(0,canonicalElfSize(payload));
const activeElfSha256=crypto.createHash('sha256').update(canonical).digest('hex');
const binding={programId:PROGRAM,programData,deploymentSlot,activeElfSha256,expectedProgramData:EXPECTED_PROGRAM_DATA,expectedActiveElfSha256:EXPECTED_ELF,exactProgramDataMatch:programData===EXPECTED_PROGRAM_DATA,exactElfMatch:activeElfSha256===EXPECTED_ELF,rpc:programResponse.endpoint,publicChainTransactions:0};
fs.writeFileSync(`${OUT}/BINDING.json`,JSON.stringify(binding,null,2)+'\n');
if(!binding.exactProgramDataMatch||!binding.exactElfMatch)throw new Error(`active deployment changed: ${JSON.stringify(binding)}`);

const rows=[],pages=[];let before,reachedDeployment=false;
for(let page=0;page<MAX_PAGES;page++){
  const options={limit:1000,commitment:'finalized'};if(before)options.before=before;
  const response=await rpc('getSignaturesForAddress',[ORACLE,options]);
  const pageRows=response.result??[];
  pages.push({page,endpoint:response.endpoint,count:pageRows.length,firstSlot:pageRows[0]?.slot,lastSlot:pageRows.at(-1)?.slot});
  for(const row of pageRows){if(Number(row.slot)<DEPLOYMENT_SLOT){reachedDeployment=true;break}rows.push(row)}
  console.log(`INDEX_PAGE=${page} ROWS=${rows.length} LAST_SLOT=${pageRows.at(-1)?.slot}`);
  if(reachedDeployment||pageRows.length<1000)break;
  before=pageRows.at(-1).signature;
  await sleep(75);
}
rows.reverse();
const summary={verdict:rows.length>=10000?'PASS_INDEX':'FAIL_INDEX_TOO_SMALL',oracle:ORACLE,rows:rows.length,reachedDeployment,oldest:rows[0]??null,newest:rows.at(-1)??null,publicChainTransactions:0};
fs.writeFileSync(`${OUT}/signatures.json`,JSON.stringify(rows));
fs.writeFileSync(`${OUT}/PAGES.json`,JSON.stringify(pages,null,2)+'\n');
fs.writeFileSync(`${OUT}/INDEX_SUMMARY.json`,JSON.stringify(summary,null,2)+'\n');
console.log(summary);
if(summary.verdict!=='PASS_INDEX')process.exit(1);
