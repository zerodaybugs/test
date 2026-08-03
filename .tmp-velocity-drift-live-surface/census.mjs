import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {Connection,Keypair,PublicKey} from '@solana/web3.js';
import * as velocity from '@velocity-exchange/sdk';
import * as drift from '@drift-labs/sdk';

const OUT=path.resolve(process.env.OUT_DIR??'evidence');
const VELOCITY_PROGRAM=new PublicKey('vELoC1audYbSYVRXn1vPaV8Axoa9oU6BYmNGZZBDZ1P');
const DRIFT_PROGRAM=new PublicKey('dRiftyHA39MWEi3m9aunc5MzRF1JYuBsbn6VPcn33UH');
const ENDPOINTS=['https://api.mainnet-beta.solana.com','https://solana-rpc.publicnode.com','https://solana.drpc.org','https://1rpc.io/solana','https://mainnet-beta.solflare.network'];
const hash=(x)=>crypto.createHash('sha256').update(x).digest('hex');
const id=(a,s)=>hash(Buffer.from(`${a}:${s}`)).slice(0,24);
const to58=(v)=>v?.toBase58?.()??(v?String(v):null);
const auth=(a)=>to58(a.authorityPubkey??a.authority_pubkey??a.authority??a.userAuthority??a.user_authority??a.owner);
const sub=(a)=>Number(a.subAccountId??a.sub_account_id??a.subaccountId??a.subAccount??a.subaccount??0);
const nz=(v)=>{try{return BigInt(v?.toString?.()??v??0)!==0n;}catch{return false;}};
const variant=(v)=>v&&typeof v==='object'?Object.keys(v)[0]??'unknown':String(v??'unknown');
const write=(name,v)=>fs.writeFileSync(path.join(OUT,name),JSON.stringify(v,null,2)+'\n');
const sleep=(ms)=>new Promise((resolve)=>setTimeout(resolve,ms));
fs.mkdirSync(OUT,{recursive:true});

async function raw(endpoint,method,params,timeoutMs=180000){
  const controller=new AbortController();
  const timer=setTimeout(()=>controller.abort(),timeoutMs);
  try{
    const response=await fetch(endpoint,{method:'POST',headers:{'content-type':'application/json','user-agent':'Velocity-Drift-Live-Surface/1.1'},body:JSON.stringify({jsonrpc:'2.0',id:1,method,params}),signal:controller.signal});
    const text=await response.text();
    if(!response.ok)throw new Error(`HTTP ${response.status}: ${text.slice(0,300)}`);
    const body=JSON.parse(text); if(body.error)throw new Error(JSON.stringify(body.error)); return body.result;
  }finally{clearTimeout(timer);}
}

async function buildClients(){
  const attempts=[];
  for(const endpoint of ENDPOINTS){
    let vc,dc;
    try{
      const slot=await raw(endpoint,'getSlot',[{commitment:'finalized'}]);
      const genesisHash=await raw(endpoint,'getGenesisHash',[]);
      for(const program of [VELOCITY_PROGRAM,DRIFT_PROGRAM]){
        const info=await raw(endpoint,'getAccountInfo',[program.toBase58(),{encoding:'base64',commitment:'finalized'}]);
        if(!info?.value?.executable)throw new Error(`program missing/non-executable ${program.toBase58()}`);
      }
      const connection=new Connection(endpoint,'finalized');
      velocity.initialize({env:'mainnet-beta'});
      const vLoader=new velocity.BulkAccountLoader(connection,'finalized',10000);
      vc=new velocity.VelocityClient({connection,wallet:new velocity.Wallet(Keypair.generate()),env:'mainnet-beta',programID:VELOCITY_PROGRAM,opts:{commitment:'finalized',preflightCommitment:'finalized'},accountSubscription:{type:'polling',accountLoader:vLoader},activeSubAccountId:0,subAccountIds:[],userStats:false});
      if(!await vc.subscribe())throw new Error('Velocity subscribe false');
      const dLoader=new drift.BulkAccountLoader(connection,'finalized',10000);
      dc=new drift.DriftClient({connection,wallet:new drift.Wallet(Keypair.generate()),env:'mainnet-beta',programID:DRIFT_PROGRAM,opts:{commitment:'finalized',preflightCommitment:'finalized'},accountSubscription:{type:'polling',accountLoader:dLoader},activeSubAccountId:0,subAccountIds:[],userStats:false});
      if(!await dc.subscribe())throw new Error('Drift subscribe false');
      attempts.push({endpoint,ok:true,slot,genesisHash});
      return {endpoint,slot,genesisHash,vc,dc,attempts};
    }catch(error){
      attempts.push({endpoint,ok:false,error:`${error.name}: ${error.message}`});
      if(vc)try{await vc.unsubscribe();}catch{}
      if(dc)try{await dc.unsubscribe();}catch{}
      await sleep(750);
    }
  }
  throw new Error(`all endpoints failed: ${JSON.stringify(attempts)}`);
}

function summarizeUser(label,row){
  const a=row.account; const authority=auth(a),subAccountId=sub(a);
  const spots=(a.spotPositions??a.spot_positions??[]).filter((p)=>nz(p.scaledBalance??p.scaled_balance));
  const perps=(a.perpPositions??a.perp_positions??[]).filter((p)=>nz(p.baseAssetAmount??p.base_asset_amount)||nz(p.quoteAssetAmount??p.quote_asset_amount)||nz(p.lpShares??p.lp_shares));
  const orders=(a.orders??[]).filter((o)=>Number(o.orderId??o.order_id??0)>0&&variant(o.status)!=='init');
  return {label,authority,subAccountId,identityHash:authority?id(authority,subAccountId):null,hasValueBearingState:spots.length>0||perps.length>0||orders.length>0,spotCount:spots.length,perpCount:perps.length,orderCount:orders.length,lastActiveSlot:String(a.lastActiveSlot?.toString?.()??a.last_active_slot?.toString?.()??0)};
}

async function signedPopulation(client){
  const namespaces=Object.keys(client.program.account).filter((n)=>/signed.*msg/i.test(n)).sort();
  const rows=[],errors=[];
  for(const namespace of namespaces){
    try{for(const row of await client.program.account[namespace].all())rows.push({namespace,authority:auth(row.account),orderCapacity:Number(row.account.signedMsgOrderData?.length??row.account.signed_msg_order_data?.length??0)});}
    catch(error){errors.push({namespace,error:`${error.name}: ${error.message}`});}
  }
  return {namespaces,rows,errors};
}

const ctx=await buildClients();
try{
  const velocityUsers=(await ctx.vc.program.account.user.all()).map((r)=>summarizeUser('velocity',r));
  const driftUsers=(await ctx.dc.program.account.user.all()).map((r)=>summarizeUser('drift',r));
  const velocitySigned=await signedPopulation(ctx.vc);
  const driftSigned=await signedPopulation(ctx.dc);
  const velocityByKey=new Map(velocityUsers.filter((u)=>u.authority).map((u)=>[`${u.authority}:${u.subAccountId}`,u]));
  const velocityByAuthority=new Map();
  for(const u of velocityUsers.filter((u)=>u.authority)){if(!velocityByAuthority.has(u.authority))velocityByAuthority.set(u.authority,[]);velocityByAuthority.get(u.authority).push(u);}
  const driftByKey=new Map(driftUsers.filter((u)=>u.authority).map((u)=>[`${u.authority}:${u.subAccountId}`,u]));
  const exact=[];
  for(const [key,vu] of velocityByKey){const du=driftByKey.get(key);if(du)exact.push({identityHash:vu.identityHash,subAccountId:vu.subAccountId,velocityHasValueBearingState:vu.hasValueBearingState,driftHasValueBearingState:du.hasValueBearingState,velocitySpotCount:vu.spotCount,velocityPerpCount:vu.perpCount,velocityOpenOrderCount:vu.orderCount,driftSpotCount:du.spotCount,driftPerpCount:du.perpCount,driftOpenOrderCount:du.orderCount,velocityLastActiveSlot:vu.lastActiveSlot,driftLastActiveSlot:du.lastActiveSlot});}
  const driftSignedToVelocity=[];
  for(const ds of driftSigned.rows.filter((x)=>x.authority)){for(const vu of velocityByAuthority.get(ds.authority)??[])driftSignedToVelocity.push({identityHash:vu.identityHash,subAccountId:vu.subAccountId,driftSignedNamespace:ds.namespace,driftSignedOrderCapacity:ds.orderCapacity,velocityHasValueBearingState:vu.hasValueBearingState,velocitySpotCount:vu.spotCount,velocityPerpCount:vu.perpCount,velocityOpenOrderCount:vu.orderCount,velocityLastActiveSlot:vu.lastActiveSlot});}
  const velocitySignedAuthorities=new Set(velocitySigned.rows.map((r)=>r.authority).filter(Boolean));
  const signedBoth=driftSigned.rows.filter((r)=>r.authority&&velocitySignedAuthorities.has(r.authority)).map((r)=>({authorityHash:hash(Buffer.from(r.authority)).slice(0,24),driftNamespace:r.namespace,driftOrderCapacity:r.orderCapacity,velocitySignedCount:velocitySigned.rows.filter((v)=>v.authority===r.authority).length}));
  const result={status:'PASS_READ_ONLY_VELOCITY_DRIFT_LIVE_SURFACE',endpoint:ctx.endpoint,finalizedSlot:ctx.slot,genesisHash:ctx.genesisHash,velocityProgramId:VELOCITY_PROGRAM.toBase58(),driftProgramId:DRIFT_PROGRAM.toBase58(),velocityUsers:velocityUsers.length,driftUsers:driftUsers.length,velocitySignedAccounts:velocitySigned.rows.length,driftSignedAccounts:driftSigned.rows.length,exactAuthoritySubaccountOverlapCount:exact.length,exactOverlapBothValueBearingCount:exact.filter((x)=>x.velocityHasValueBearingState&&x.driftHasValueBearingState).length,driftSignedAuthorityMappedVelocityUserCount:driftSignedToVelocity.length,driftSignedAuthorityMappedValueBearingVelocityUserCount:driftSignedToVelocity.filter((x)=>x.velocityHasValueBearingState).length,signedAuthorityBothProtocolsCount:signedBoth.length,currentLiveVictimSurface:driftSignedToVelocity.some((x)=>x.velocityHasValueBearingState),redactedExactOverlap:exact,redactedDriftSignedToVelocity:driftSignedToVelocity,redactedSignedBothProtocols:signedBoth,namespaceErrors:{velocity:velocitySigned.errors,drift:driftSigned.errors},connectionAttempts:ctx.attempts,safety:{productionPrivateKeysLoaded:0,ephemeralReadOnlyKeypairsGenerated:2,transactionsConstructed:0,transactionsSigned:0,transactionsSent:0,publicChainWrites:0,rpcMethods:['getSlot','getGenesisHash','getAccountInfo','getProgramAccounts']}};
  write('FINAL_GATE.json',result);
  write('PUBLIC_SUMMARY.json',{status:result.status,finalizedSlot:result.finalizedSlot,velocityUsers:result.velocityUsers,driftUsers:result.driftUsers,velocitySignedAccounts:result.velocitySignedAccounts,driftSignedAccounts:result.driftSignedAccounts,exactAuthoritySubaccountOverlapCount:result.exactAuthoritySubaccountOverlapCount,exactOverlapBothValueBearingCount:result.exactOverlapBothValueBearingCount,driftSignedAuthorityMappedVelocityUserCount:result.driftSignedAuthorityMappedVelocityUserCount,driftSignedAuthorityMappedValueBearingVelocityUserCount:result.driftSignedAuthorityMappedValueBearingVelocityUserCount,signedAuthorityBothProtocolsCount:result.signedAuthorityBothProtocolsCount,currentLiveVictimSurface:result.currentLiveVictimSurface,publicChainWrites:0});
  console.log(JSON.stringify(result,null,2));
}finally{await ctx.vc.unsubscribe();await ctx.dc.unsubscribe();}
