
const http = require("http");
const base64url = require('base64url');
const crypto    = require('crypto');

const { v4: uuidv4 } = require('uuid');

const port = 3000;
const server = http.createServer();

const { Fido2Lib } = require("fido2-lib");

const FIDO_RP_NAME = process.env.FIDO_RP_NAME || "Local FIDO Host";
const FIDO_ORIGIN = process.env.FIDO_ORIGIN || "http://localhost"+(port===80||port===443?"":":"+port);
let fido2lib = new Fido2Lib({
  rpName: FIDO_RP_NAME
});

let database = {};//use json as DB, all data will lost after restart program.

let sessions = {};

server.on('request', AppController);

server.listen(port);
console.log(`Started server: ${port}`);


async function AppController(request, response) {
  const url = new URL(request.url, `http://${request.headers.host}`)
    
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
        authnOptions.challenge = base64url.encode(uuidv4())
    
        let allowCredentials = [];
        for(let authr of database[username].attestation) {
            allowCredentials.push({
              type: 'public-key',
              id: authr.credId,
              transports: ['internal', 'hybrid', 'usb', 'nfc', 'ble']// can be overrided by client
            })
        }
        authnOptions.allowCredentials = allowCredentials;
        console.log(authnOptions);
    
        sessions[authnOptions.challenge] = {
          'challenge': authnOptions.challenge,
          'username': username
        };
    
        authnOptions.status = 'ok';
    
        response.end(JSON.stringify(authnOptions));
      }else if(url.pathname == '/assertion/result'){
        const body = await loadJsonBody(request)

        const cda=new Uint8Array(base64url.toBuffer(body.response.clientDataJSON))
        const cltdatatxt = String.fromCharCode.apply("", cda)
        const clientData = JSON.parse(cltdatatxt)
    
        let attestation = null;
        for( let i = 0 ; i < database[sessions[clientData.challenge].username].attestation.length ; i++ ){
          if( database[sessions[clientData.challenge].username].attestation[i].credId == body.id ){
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
    
        body.rawId = new Uint8Array(base64url.toBuffer(body.rawId)).buffer;
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
        registrationOptions.challenge = base64url.encode(uuidv4())//use challenge as session id

        //Prevent register same authenticator
        if(database[username] && database[username].attestation){
          let excludeCredentials = [];
          for(let authr of database[username].attestation) {
            excludeCredentials.push({
                type: 'public-key',
                id: authr.credId,
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

        sessions[registrationOptions.challenge] = {
          'challenge': registrationOptions.challenge,
          'username': username
        };

        registrationOptions.status = 'ok';

        response.end(JSON.stringify(registrationOptions));

      }else if( url.pathname == '/attestation/result'){
        const body = await loadJsonBody(request)
        
        const cda=new Uint8Array(base64url.toBuffer(body.response.clientDataJSON))
        const cltdatatxt = String.fromCharCode.apply("", cda)
        const clientData = JSON.parse(cltdatatxt)

        const cur_session = sessions[clientData.challenge]
        delete sessions[clientData.challenge]

        let attestationExpectations = {
            challenge: cur_session.challenge,
            origin: FIDO_ORIGIN,
            factor: "either"
        };
        body.rawId = new Uint8Array(base64url.toBuffer(body.rawId)).buffer;
        let regResult = await fido2lib.attestationResult(body, attestationExpectations);
        console.log(regResult);

        const credId = base64url.encode(regResult.authnrData.get('credId'));
        const aaguid = buf2hex(regResult.authnrData.get('aaguid'))//No required info for reg/auth
        const counter = regResult.authnrData.get('counter');
        database[cur_session.username].attestation.push({
            publickey : regResult.authnrData.get('credentialPublicKeyPem'),
            counter : counter,
            fmt : regResult.authnrData.get('fmt'),
            credId : credId,
            aaguid : aaguid
        });
    
        let rtn='';
        if(regResult.audit.complete) {
          database[cur_session.username].registered = true
    
          rtn = {
            'status': 'ok',
            credId: credId,
            counter: counter
          };
        } else {
          rtn = {
            'status': 'failed',
            'message': 'Can not authenticate signature!'
          };
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