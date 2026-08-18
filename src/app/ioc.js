/* ================= IOC EXTRACTION ================= */
/* Regex-based indicator classifier, ported from Skyhawk's ingest.js IOC block
   plus a CVE pattern. Used to auto-highlight indicators in ticket bodies and
   hunt-map observation notes, and to feed the response advisor's IOC-blocking
   phase (see advisor.js). */
const IOC_SHA256=/\b[a-f0-9]{64}\b/gi;
const IOC_SHA1=/\b[a-f0-9]{40}\b/gi;
const IOC_MD5=/\b[a-f0-9]{32}\b/gi;
const IOC_IPV4=/\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
const IOC_DOMAIN=/\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|top|xyz|ru|cn|info|biz|io|co|us|uk|de|nl|onion|su|cc|tk|ml|ga|cf|pw|club|site|online|live|link)\b/gi;
const IOC_URL=/\bhttps?:\/\/[^\s"'<>)\]]+/gi;
const IOC_CVE=/\bCVE-\d{4}-\d{4,7}\b/gi;
const IOC_PRIVATE_IP=/^(?:10\.|127\.|0\.|169\.254\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|22[4-9]\.|2[3-5]\d\.|255\.)/;

function extractIocs(text){
 const out=[],seen=new Set();
 if(!text)return out;
 const push=(type,v)=>{const k=type+':'+v.toLowerCase();if(seen.has(k))return;seen.add(k);out.push({type,value:v});};
 (text.match(IOC_CVE)||[]).forEach(v=>push('cve',v.toUpperCase()));
 (text.match(IOC_SHA256)||[]).forEach(v=>push('sha256',v));
 (text.match(IOC_URL)||[]).forEach(v=>push('url',v));
 (text.match(IOC_IPV4)||[]).forEach(v=>{if(!IOC_PRIVATE_IP.test(v))push('ipv4',v);});
 (text.match(IOC_DOMAIN)||[]).forEach(v=>push('domain',v));
 (text.match(IOC_SHA1)||[]).forEach(v=>{if(v.length===40)push('sha1',v);});
 (text.match(IOC_MD5)||[]).forEach(v=>{if(v.length===32)push('md5',v);});
 return out;
}

/* esc()-first, then regex-highlight the escaped string — same convention hl() uses for SPL. */
function highlightIocs(text){
 return esc(text)
  .replace(IOC_CVE,'<span class="ioc ioc-cve">$&</span>')
  .replace(IOC_SHA256,'<span class="ioc ioc-hash">$&</span>')
  .replace(IOC_URL,'<span class="ioc ioc-url">$&</span>')
  .replace(IOC_IPV4,m=>IOC_PRIVATE_IP.test(m)?m:`<span class="ioc ioc-ip">${m}</span>`)
  .replace(IOC_DOMAIN,'<span class="ioc ioc-domain">$&</span>');
}
