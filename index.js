
/**
 * JWKS -> RSA 参数转换（全部JWKS字段都经过Base64 URL编码）
 * JSWK字段  RSA参数
 * n       : modulus                    模数
 * e       : public exponent            公钥指数
 * d       : private exponent           私钥指数
 * p       : secret prime factor        第一个要保密的大素数
 * q       : secret prime factor        第二个要保密的大素数
 * dp      : first factor CRT exponent  CRT参数dP，即 d mod (p-1)
 * dq      : second factor CRT exponent CRT参数dQ，即 d mod (q-1)
 * qi      : first CRT coefficient      CRT参数qInv，即 (1/q) mod p
 * 
 * 其中，公钥只需要参数n, e，签名验证仅需公钥，jwks也仅提供公钥
 * 
 * https://www.di-mgt.com.au/crt.html#chineseremaindertheorem
 */

const NodeRSA = require('node-rsa')
const base64url = require('base64url')
const fetch = require('node-fetch')

const JWKS_URL_PATH = "https://account.cambricon.com/jwks"

const DEMO_ID_TOKEN = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Il9OOHpBaTI2eUNtVkRydk03NkFvWDgzZFBibzQ2VVV5RmN6SVdSQWJkZW8ifQ.eyJzdWIiOiI1RGJGZnpub3pheVBQMDhaNW9TOV9ZNk4iLCJhdF9oYXNoIjoiRUQ0dUQtNERhTlNHdXVDMHRGSEtxQSIsImF1ZCI6ImRlbW9pZCIsImV4cCI6MTU4NTcyNTY2OSwiaWF0IjoxNTg1NzIyMDY5LCJpc3MiOiJodHRwOi8vbG9jYWxob3N0In0.JttELi8c1dZVonkGqwolYJYL0MWhhlMg4zqA_vS3NBn0xPPvgQKIibP5hJM4d3TZXFSA_rdUDvOjuzQwLRPzmaoolMqzn7IVfWxi-lvmykltzQ-PV1xzSTjLNZgVI3hnl-pp5rCsrFzxGkD10WMCmShbLugodgpOSm-EHR_-BBhA_Ffup7Q5fsxTa4k98QSSCODbmew3DGc5D5X_Qv8o0TEM8xZZV4kHkEtd7KsJqrXnY8MR4oS5tORBlNxwWvQJiCxW1HpIIDGfEKvHA0jXq-Bzz-UixuS22khSfTiHMZaHb5AKRScjZB09WY1ctb1ehVoZHaPsdDrg2T9-cn3uPg"

const ID_TOKEN_HEADER    = JSON.parse(base64url.decode(DEMO_ID_TOKEN.split('.')[0]))
const ID_TOKEN_PAYLOAD   = JSON.parse(base64url.decode(DEMO_ID_TOKEN.split('.')[1]))
const ID_TOKEN_SIGNATURE = DEMO_ID_TOKEN.split('.')[2]

fetch(JWKS_URL_PATH, { method: "Get" }).then(res => res.json()).then((json) => {
    var targetKeyComponents = null
    json.keys.every(key =>{
        if(key.kid == ID_TOKEN_HEADER.kid) { targetKeyComponents = key; return false }
        return true
    })
    if(targetKeyComponents == null) console.log('Target kid doesn\'t exist in jwks.json.')

    const key = new NodeRSA()
    key.importKey({
        n: Buffer.from(targetKeyComponents.n, 'base64'),
        e: Buffer.from(targetKeyComponents.e, 'base64'),
    }, 'components-public')

    console.log(ID_TOKEN_HEADER)
    console.log(ID_TOKEN_PAYLOAD)
    console.log({sig: key.decryptPublic(ID_TOKEN_SIGNATURE, 'base64')})
})

/**
 * 输出：
 * 
 * {
 *   alg: 'RS256',
 *   typ: 'JWT',
 *   kid: '_N8zAi26yCmVDrvM76AoX83dPbo46UUyFczIWRAbdeo'
 * }
 * {
 *   sub: '5DbFfznozayPP08Z5oS9_Y6N',
 *   at_hash: 'ED4uD-4DaNSGuuC0tFHKqA',
 *   aud: 'demoid',
 *   exp: 1585725669,
 *   iat: 1585722069,
 *   iss: 'http://localhost'
 * }
 * {
 *   sig: 'MDEwDQYJYIZIAWUDBAIBBQAEIIHYI1dI5KkdJkXgkWo6lr64Z/hawqgGwtDXgXm/XrRx'
 * }
 * 
 */