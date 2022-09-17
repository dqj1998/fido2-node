
const https = require("https");
const base64url = require('base64url');
const crypto    = require('crypto');
const fs        = require('fs');

const { v4: uuidv4 } = require('uuid');

//const port = 3000;
//const server = http.createServer();
const port = 443;
const options = {
  key: fs.readFileSync('ssl/dqj-macpro.key.pem'),
  cert: fs.readFileSync('ssl/dqj-macpro.crt')
};
const server = https.createServer(options)

const { Fido2Lib } = require("fido2-lib");

const FIDO_RP_NAME = process.env.FIDO_RP_NAME || "mac.dqj-macpro.com FIDO Host";
const FIDO_ORIGIN = process.env.FIDO_ORIGIN || "https://mac.dqj-macpro.com"+(port===80||port===443?"":":"+port);//"http://localhost"+(port===80||port===443?"":":"+port);
let fido2lib = new Fido2Lib({
  rpName: FIDO_RP_NAME,
  timeout: 300 * 1000 //ms
});

let database = {};//use json as DB, all data will lost after restart program.

let sessions = {};

server.on('request', AppController);

server.listen(port);
console.log(`Started server: ${port}`);


async function AppController(request, response) {
  const url = new URL(request.url, `https://${request.headers.host}`)
    
  if(request.method === 'GET') {
    let html=""
    try{
        let real_path;
        if(url.pathname === '/')real_path='fido2.html'
        else real_path = url.pathname
        html = require('fs').readFileSync('views/'+real_path);
    }catch(ex){
        html=ex.message
    }
    response.writeHead(200, {'Content-Type': 'text/html'});
    response.end(html);
  }else if(request.method === 'POST') {
    try{
      let real_path;
      if(url.pathname == '/assertion/options'){
        const body = await loadJsonBody(request)
    
        let username = body.username;
    
        if(!database[username] || !database[username].registered) {
          response.end(JSON.stringify({
            'status': 'failed',
            'message': `Username ${username} does not exist`
          }));
          return
        }
    
        let authnOptions = await fido2lib.assertionOptions(body);
        let challengeTxt = uuidv4()
        let challengeBase64 = base64url.encode(challengeTxt) //To fit to the challenge of CollectedClientData
        authnOptions.challenge = Array.from(new TextEncoder().encode(challengeTxt))
    
        let allowCredentials = [];
        for(let authr of database[username].attestation) {
            allowCredentials.push({
              type: 'public-key',
              id: Array.from(new Uint8Array(authr.credId)),
              transports: ['internal', 'hybrid', 'usb', 'nfc', 'ble']// can be overrided by client
            })
        }
        authnOptions.allowCredentials = allowCredentials;
        console.log(authnOptions);
    
        sessions[challengeBase64] = {
          'challenge': authnOptions.challenge,
          'username': username
        };
    
        authnOptions.status = 'ok';
    
        response.end(JSON.stringify(authnOptions));
      }else if(url.pathname == '/assertion/result'){
        const body = await loadJsonBody(request)

        /*const cda=new Uint8Array(base64url.toBuffer(body.response.clientDataJSON))
        const cltdatatxt = String.fromCharCode.apply("", cda)
        console.log('clientDataJSON:'); console.log(cltdatatxt)*/
        const clientData = JSON.parse(body.response.clientDataJSON)

        body.response.authenticatorData = new Uint8Array(body.response.authenticatorData).buffer
        body.response.signature = new Uint8Array(body.response.signature).buffer
        body.response.userHandle = new TextDecoder().decode(new Uint8Array(body.response.userHandle).buffer)   
        body.response.clientDataJSON = Uint8Array.from(new TextEncoder().encode(body.response.clientDataJSON)).buffer
    
        let attestation = null;
        for( let i = 0 ; i < database[sessions[clientData.challenge].username].attestation.length ; i++ ){
          //let debugId=new Uint8Array(base64url.toBuffer(body.id)).buffer//for debug
          if( body.rawId ){
            body.rawId = new Uint8Array(body.rawId).buffer;
          }else{
            body.rawId = new Uint8Array(base64url.toBuffer(body.id)).buffer
          }          
          let reqId = body.rawId
          let dbId = database[sessions[clientData.challenge].username].attestation[i].credId         
          if (dbId.byteLength == reqId.byteLength && equlsArrayBuffer(reqId, dbId)) {
            attestation = database[sessions[clientData.challenge].username].attestation[i];
            break;
          }
        }

        if( !attestation ){
          let rtn = {
            'status': 'failed',
            'message': 'key is not found.'
          }
          response.end(JSON.stringify(rtn));
          return
        }

        const cur_session = sessions[clientData.challenge]
        delete sessions[clientData.challenge]

        let assertionExpectations = {
          challenge: cur_session.challenge,
          origin: FIDO_ORIGIN,
          factor: "either",
          publicKey: attestation.publickey,
          prevCounter: attestation.counter,
          userHandle: database[cur_session.username].id //null
        };    
        
        let authnResult = await fido2lib.assertionResult(body, assertionExpectations);
        console.log(authnResult);
    
        let rtn='';
        if(authnResult.audit.complete) {
          attestation.counter = authnResult.authnrData.get('counter');    
          
          rtn = {
            'status': 'ok',
            credId: body.id,
            counter: attestation.counter
          }
        } else {
          rtn = {
            'status': 'failed',
            'message': 'Can not authenticate signature!'
          }
        }
        
        response.end(JSON.stringify(rtn));
      }else if(url.pathname === '/attestation/options'){
        const body = await loadJsonBody(request)

        let username = body.username;

        let userid;
        if(database[username]) {
          userid = database[username].id;
        }else{
          userid = uuidv4();
        }

        let registrationOptions = await fido2lib.attestationOptions();
        let challengeTxt = uuidv4()
        let challengeBase64 = base64url.encode(challengeTxt) //To fit to the challenge of CollectedClientData
        registrationOptions.challenge = Array.from(new TextEncoder().encode(challengeTxt)) //base64url.encode(uuidv4())//use challenge as session id

        registrationOptions.authenticatorSelection = body.authenticatorSelection

        //Prevent register same authenticator
        if(database[username] && database[username].attestation){
          let excludeCredentials = [];
          for(let authr of database[username].attestation) {
            excludeCredentials.push({
                type: 'public-key',
                id: Array.from(new Uint8Array(authr.credId)),
                transports: ['internal', 'hybrid', 'usb', 'nfc', 'ble']
              })
          }
          registrationOptions.excludeCredentials = excludeCredentials
        }        

        registrationOptions.user.id = userid;
        registrationOptions.user.name = username;
        registrationOptions.user.displayName = body.displayName?body.displayName:username;

        console.log(registrationOptions);

        if(!database[username]){
          database[username] = {
            'name': username,
            'registered': false,
            'id': registrationOptions.user.id,
            'attestation': []
          };
        }        

        sessions[challengeBase64] = {
          'challenge': registrationOptions.challenge,
          'username': username
        };

        registrationOptions.status = 'ok';

        response.end(JSON.stringify(registrationOptions));

      }else if( url.pathname == '/attestation/result'){
        const body = await loadJsonBody(request)
        
        /*const cda=new Uint8Array(base64url.toBuffer(body.response.clientDataJSON))
        const cltdatatxt = String.fromCharCode.apply("", cda)
        console.log('clientDataJSON:'); console.log(cltdatatxt)*/
        const clientData = JSON.parse(body.response.clientDataJSON)

        /*const tpAtt = typeof body.response.attestationObject //for debug
        const attobj=new Buffer.from(body.response.attestationObject)
        var ab = new ArrayBuffer(attobj.length);
        var view = new Uint8Array(ab);
        for (var i = 0; i < attobj.length; ++i) {
            view[i] = attobj[i];
        }*/
        body.rawId = new Uint8Array(body.rawId).buffer; //new Uint8Array(base64url.toBuffer(body.rawId)).buffer;
        body.response.attestationObject = new Uint8Array(body.response.attestationObject).buffer        
        body.response.clientDataJSON = Uint8Array.from(new TextEncoder().encode(body.response.clientDataJSON)).buffer
        
        const cur_session = sessions[clientData.challenge]
        delete sessions[clientData.challenge]

        let attestationExpectations = {
            challenge: cur_session.challenge,
            origin: FIDO_ORIGIN,
            factor: "either"
        };
        
        let regResult = await fido2lib.attestationResult(body, attestationExpectations);
        console.log(regResult);

        const credId = regResult.authnrData.get('credId')
        const aaguid = buf2hex(regResult.authnrData.get('aaguid'))//No required info for reg/auth
        const counter = regResult.authnrData.get('counter');
        database[cur_session.username].attestation.push({
            publickey : regResult.authnrData.get('credentialPublicKeyPem'),
            counter : counter,
            fmt : regResult.authnrData.get('fmt'),
            credId : credId,
            aaguid : aaguid
        });
    
        let rtn={};
        if(regResult.audit.complete) {
          database[cur_session.username].registered = true
    
          rtn.status = 'ok',
          rtn.counter = counter
          rtn.credId = Array.from(new Uint8Array(regResult.authnrData.get('credId')))
        } else {
          rtn.status ='failed',
          rtn.message = 'Can not authenticate signature!'
        }

        response.end(JSON.stringify(rtn));
      }
    }catch(ex){
      response.end(ex.message);
    }
  }
  
};

function buf2hex(buffer) { // buffer is an ArrayBuffer
  return [...new Uint8Array(buffer)]
      .map(x => x.toString(16).padStart(2, '0'))
      .join('');
}

function equlsArrayBuffer(a, b){
  if(a.byteLength!=a.byteLength) return false;
  for(var i=0; a.byteLength > i; i++){
    if(a[i]!=b[i])return false;
  }
  return true 
}

async function loadJsonBody(request){
  const buffers = [];

  for await (const chunk of request) {
    buffers.push(chunk);
  }

  const bodytxt = Buffer.concat(buffers).toString();

  const body = JSON.parse(bodytxt);
  console.log(body);

  return body;
}