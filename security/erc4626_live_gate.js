'use strict';
const fs = require('fs');
const { ethers } = require('ethers');

const OUT = 'erc4626-live-gate';
const RPCS = [
  'https://eth.drpc.org',
  'https://eth.llamarpc.com',
  'https://1rpc.io/eth',
  'https://ethereum-rpc.publicnode.com'
];
const TARGETS = [
  { label: 'ynETHx', market: '0x9d08e943828DA4BCc9681eda5d7e4D4994cC24b8', gt: '0x15C425E4ABe46670ffb4094B0F1e994eaFca3e52', collateral: '0x657d9ABA1DBb59e53f9F3eCAA878447dCfC96dCb', feed: '0x5FDaa369D623d86191105435c7DA03F25417753a', order: '0x562046484a1F9128836Bb265801C4039DABD6b7E' },
  { label: 'srUSDat', market: '0x546C6395be470FAeA356706d66c89429ee0D1Ef4', gt: '0xFC173D84fBA6Ee2B8cA6871C528a8C9890d46a20', collateral: '0xFaa9a0e1Db9E22AE3A20B2B58a68DC24D053d066', feed: '0x892f5d46c4291cC854820ebA04b72362794693d0', order: '0x0000000000000000000000000000000000000000' },
  { label: 'sUSDat', market: '0x148FfE0c1746Db30C7fB01Ff58f4E2a9F61c2058', gt: '0x8dCC96F70F7B44C1c69230e1fA018b50dec95011', collateral: '0xD166337499E176bbC38a1FBd113Ab144e5bd2Df7', feed: '0x86161206b6172E9919A54d7a384D7A4526d6C8c6', order: '0x0000000000000000000000000000000000000000' },
  { label: 'ROY-ST-stcUSD', market: '0x17FbF5883eF9a8e0a756de8FDc95A4B5E20A3DA8', gt: '0x36B5E3E5723d4EB38de3bd2dbd6E87FeF1862863', collateral: '0xa7Da92685ea436276B2e87aE12E5eE6DABaD5bB5', feed: '0x0534fA9b1234CbB166eA60B7977CAFC75264C9aF', order: '0x0000000000000000000000000000000000000000' },
  { label: 'ROY-ST-syrupUSDC', market: '0x57e92D2c565BaF64958a4fC820563621Dfb8f88D', gt: '0x2b16B1d7124e872687e5466ea84A6FFcC4F3a2a4', collateral: '0x66182442522D3049A941035190C315379c959250', feed: '0x57B520EC7D09A2F63d6789e5541a6C4a84c6825d', order: '0x0000000000000000000000000000000000000000' }
];
const ZERO = ethers.constants.AddressZero;
const feedAbi = [
  'function asset() view returns(address)',
  'function assetPriceFeed() view returns(address)',
  'function latestRoundData() view returns(uint80,int256,uint256,uint256,uint80)',
  'function decimals() view returns(uint8)', 'function description() view returns(string)',
  'function PRICE_FEED() view returns(address)', 'function MARKET() view returns(address)',
  'function aTokenToBTokenPriceFeed() view returns(address)', 'function bTokenToCTokenPriceFeed() view returns(address)'
];
const vaultAbi = [
  'function name() view returns(string)', 'function symbol() view returns(string)', 'function decimals() view returns(uint8)',
  'function asset() view returns(address)', 'function totalAssets() view returns(uint256)', 'function totalSupply() view returns(uint256)',
  'function balanceOf(address) view returns(uint256)',
  'function convertToAssets(uint256) view returns(uint256)', 'function previewRedeem(uint256) view returns(uint256)',
  'function maxRedeem(address) view returns(uint256)', 'function maxWithdraw(address) view returns(uint256)'
];
const tokenAbi = ['function symbol() view returns(string)','function decimals() view returns(uint8)','function balanceOf(address) view returns(uint256)'];
const marketAbi = ['function tokens() view returns(address ft,address xt,address gt,address collateral,address debtToken)','function config() view returns(address treasurer,uint64 maturity,(uint32,uint32,uint32,uint32,uint32,uint32) feeConfig)'];
const orderAbi = ['function tokenReserves() view returns(uint256 ftReserve,uint256 xtReserve)','function getRealReserves() view returns(uint256 ftReserve,uint256 xtReserve)'];
function ser(v){if(ethers.BigNumber.isBigNumber(v))return v.toString();if(Array.isArray(v))return v.map(ser);if(v&&typeof v==='object'){const o={};for(const[k,x]of Object.entries(v))if(!/^\d+$/.test(k))o[k]=ser(x);return o;}return v;}
async function safe(p){try{return{ok:true,value:ser(await p)}}catch(e){return{ok:false,error:String(e)}}}
async function choose(){const attempts=[];for(const url of RPCS){try{const p=new ethers.providers.JsonRpcProvider(url,1);const [n,b]=await Promise.all([p.getNetwork(),p.getBlockNumber()]);if(n.chainId!==1)throw Error('wrong chain');attempts.push({url,ok:true,block:b});return{p,url,block:b,attempts};}catch(e){attempts.push({url,ok:false,error:String(e)})}}throw Error(JSON.stringify(attempts));}
(async()=>{
  fs.mkdirSync(OUT,{recursive:true});
  const {p,url,block,attempts}=await choose();
  const header=await p.getBlock(block);
  const results=[];
  for(const t of TARGETS){
    const feed=new ethers.Contract(t.feed,feedAbi,p);const vault=new ethers.Contract(t.collateral,vaultAbi,p);const market=new ethers.Contract(t.market,marketAbi,p);
    const [feedCode,vaultCode,marketCode,feedAsset,assetPriceFeed,round,feedDecimals,description,vaultName,vaultSymbol,vaultDecimals,vaultAsset,totalAssets,totalSupply,gtShares,maxRedeem,maxWithdraw,tokens,config]=await Promise.all([
      p.getCode(t.feed,block),p.getCode(t.collateral,block),p.getCode(t.market,block),safe(feed.asset({blockTag:block})),safe(feed.assetPriceFeed({blockTag:block})),safe(feed.latestRoundData({blockTag:block})),safe(feed.decimals({blockTag:block})),safe(feed.description({blockTag:block})),safe(vault.name({blockTag:block})),safe(vault.symbol({blockTag:block})),safe(vault.decimals({blockTag:block})),safe(vault.asset({blockTag:block})),safe(vault.totalAssets({blockTag:block})),safe(vault.totalSupply({blockTag:block})),safe(vault.balanceOf(t.gt,{blockTag:block})),safe(vault.maxRedeem(t.gt,{blockTag:block})),safe(vault.maxWithdraw(t.gt,{blockTag:block})),safe(market.tokens({blockTag:block})),safe(market.config({blockTag:block}))
    ]);
    let unit=null,grossUnit=null,netUnit=null,grossGt=null,netGt=null,underlying=null,underlyingMeta=null;
    if(vaultDecimals.ok){unit=ethers.BigNumber.from(10).pow(vaultDecimals.value);grossUnit=await safe(vault.convertToAssets(unit,{blockTag:block}));netUnit=await safe(vault.previewRedeem(unit,{blockTag:block}));}
    if(gtShares.ok){grossGt=await safe(vault.convertToAssets(gtShares.value,{blockTag:block}));netGt=await safe(vault.previewRedeem(gtShares.value,{blockTag:block}));}
    if(vaultAsset.ok&&vaultAsset.value!==ZERO){underlying=vaultAsset.value;const u=new ethers.Contract(underlying,tokenAbi,p);underlyingMeta={symbol:await safe(u.symbol({blockTag:block})),decimals:await safe(u.decimals({blockTag:block}))};}
    let order=null;if(t.order!==ZERO){const o=new ethers.Contract(t.order,orderAbi,p);order={address:t.order,reserves:await safe(o.tokenReserves({blockTag:block})),realReserves:await safe(o.getRealReserves({blockTag:block}))};}
    let gapBps=null,gtGap=null;if(grossUnit?.ok&&netUnit?.ok&&!ethers.BigNumber.from(grossUnit.value).isZero())gapBps=ethers.BigNumber.from(grossUnit.value).sub(netUnit.value).mul(10000).div(grossUnit.value).toString();if(grossGt?.ok&&netGt?.ok)gtGap=ethers.BigNumber.from(grossGt.value).sub(netGt.value).toString();
    results.push(ser({...t,code:{feedHash:ethers.utils.keccak256(feedCode),feedBytes:(feedCode.length-2)/2,vaultHash:ethers.utils.keccak256(vaultCode),vaultBytes:(vaultCode.length-2)/2,marketHash:ethers.utils.keccak256(marketCode)},feed:{asset:feedAsset,assetPriceFeed,round,decimals:feedDecimals,description},vault:{name:vaultName,symbol:vaultSymbol,decimals:vaultDecimals,asset:vaultAsset,totalAssets,totalSupply,gtShares,maxRedeem,maxWithdraw,unit:unit?.toString()||null,grossUnit,netUnit,gapBps,grossGt,netGt,gtGap,underlyingMeta},market:{tokens,config},order}));
  }
  const output={generatedAt:new Date().toISOString(),scope:'READ_ONLY_NO_TRANSACTIONS',rpc:url,rpcAttempts:attempts,snapshot:{blockNumber:block,blockHash:header.hash,timestamp:header.timestamp},results};
  fs.writeFileSync(`${OUT}/result.json`,JSON.stringify(output,null,2));console.log(JSON.stringify(output,null,2));
})().catch(e=>{fs.mkdirSync(OUT,{recursive:true});fs.writeFileSync(`${OUT}/error.txt`,String(e.stack||e));console.error(e);process.exit(1)});
