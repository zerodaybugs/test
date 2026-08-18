import fs from 'node:fs';
import { SuiGrpcClient } from '@mysten/sui/grpc';
import { deepbook } from '@mysten/deepbook-v3';

const client = new SuiGrpcClient({
  network: 'mainnet',
  baseUrl: 'https://fullnode.mainnet.sui.io:443',
}).$extend(deepbook({ address: '0x0' }));
const pools = ['DEEP_USDC','DEEP_SUI','SUI_USDC','WAL_USDC','WAL_SUI','NS_USDC','NS_SUI','XBTC_USDC','IKA_USDC','USDT_USDC'];
const sleep=(ms)=>new Promise(r=>setTimeout(r,ms));
async function retry(fn){let e;for(let i=1;i<=5;i++){try{return await fn()}catch(x){e=x;if(i<5)await sleep(i*1000)}}throw e}
const out={generated_at:new Date().toISOString(),network:'mainnet',write_operations:0,pools:{}};
for(const poolKey of pools){
  const row={};
  const tasks={
    mid_price:()=>client.deepbook.midPrice(poolKey),
    whitelisted:()=>client.deepbook.whitelisted(poolKey),
    trade_params:()=>client.deepbook.poolTradeParams(poolKey),
    book_params:()=>client.deepbook.poolBookParams(poolKey),
    vault_balances:()=>client.deepbook.vaultBalances(poolKey),
    deep_price:()=>client.deepbook.getPoolDeepPrice(poolKey),
    level2_100:()=>client.deepbook.getLevel2TicksFromMid(poolKey,100),
  };
  for(const [name,fn] of Object.entries(tasks)){
    try{row[name]=await retry(fn)}catch(error){row[name+'_error']=String(error?.stack??error)}
  }
  out.pools[poolKey]=row;
}
fs.writeFileSync('MAINNET_SNAPSHOT.json',JSON.stringify(out,null,2));
