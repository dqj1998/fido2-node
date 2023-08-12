
const base64url = require('base64url');
const crypto    = require('crypto');
const fs        = require('fs');
const log4js    = require('log4js');
const utils = require("./fido2-node-lib/utils")

require('dotenv').config();

const { v4: uuidv4 } = require('uuid');

const { env } = require("process");

log4js.configure('log4js-conf.json');
const logger = log4js.getLogger();
//logger.level = process.env.LOG4JS_LEVEL;

//console.log(process.version)
logger.info('Running on nodejs:' + process.version)

const port = process.env.PORT || 443;

const mysql = require('mysql2');
const mysql_pool = mysql.createPool({
  connectionLimit : process.env.MYSQL_POOL_LIMIT || 10,
  host: process.env.MYSQL_HOST || 'localhost',
  database: process.env.MYSQL_DATABASE || 'fido2_node_db',
  user: process.env.MYSQL_USER || 'root',
  password: process.env.MYSQL_PASSWD || '',
});

var server
if(process.env.SSLKEY && process.env.SSLCRT){
  const options = {
    key: fs.readFileSync(process.env.SSLKEY),
    cert: fs.readFileSync(process.env.SSLCRT)
  };
  const https = require("https");
  server = https.createServer(options)
}else{
  const http = require("http");
  server = http.createServer({})
} 

const DEFAULT_FIDO_RPID = process.env.DEFAULT_FIDO_RPID
const FIDO_ORIGIN = process.env.FIDO_ORIGIN

const DOMAIN_JSON_FN = 'domain.json';
var domains_conf
var registeredRps
var enterpriseRps
var enterpriseAaguids
var deviceBindedKeys
var userSessionActiveTimeout
var userSessionHardTimeout
var processTimeout
var regSessionTimeout

let database = new Map();//use json as DB, all data will lost after restart program.

let user_sessions = new Map();

loadDomains();

let mapCredidUsername = {};//Link cred ids with usernames
let sessions = {};

const {mds3_client} = require("./mds3.js")

server.on('request', AppController);

server.listen(port);
//console.log(`Started server: ${port}`);
logger.info(`Started server: ${port}`);

setInterval(function(){
    clearTimeoutSessions();
  }, 
  60*1000);

function loadDomains(){
  domains_conf = JSON.parse(fs.readFileSync(DOMAIN_JSON_FN, 'utf8'));
  
  registeredRps = [];
  enterpriseRps = [];
  passkeySync = new Map();
  enterpriseAaguids = new Map();
  deviceBindedKeys = new Map();
  userSessionActiveTimeout = new Map(); //Seconds
  userSessionHardTimeout = new Map(); //Seconds
  processTimeout = new Map(); //ms
  regSessionTimeout = new Map(); //Seconds

  domains_conf.domains.forEach(element => {
    registeredRps.push(element.domain)
    
    if(element.passkey_sync){
      passkeySync.set(element.domain, element.passkey_sync)
      deviceBindedKeys.set(element.domain, false)
    }else{
      passkeySync.set(element.domain, false)

      if(element.device_bind_key)deviceBindedKeys.set(element.domain, element.device_bind_key)
      else deviceBindedKeys.set(element.domain, false)

      if(element.enterprise){
        enterpriseRps.push(element.domain)
  
        if(element.enterprise_aaguids){
          enterpriseAaguids.set(element.domain, element.enterprise_aaguids)
        }
      }
  
    } 
    

    if(element.user_session_active_timeout)userSessionActiveTimeout.set(element.domain, element.user_session_active_timeout)
    else userSessionActiveTimeout.set(element.domain, 15*60) //Seconds
    if(element.user_session_hard_timeout)userSessionHardTimeout.set(element.domain, element.user_session_hard_timeout)
    else userSessionHardTimeout.set(element.domain, 24*60*60) //Seconds
    if(element.process_timeout)processTimeout.set(element.domain, element.process_timeout*1000)
    else processTimeout.set(element.domain, 10*60*1000) //ms
    if(element.registration_session_timeout)regSessionTimeout.set(element.domain, element.registration_session_timeout)
    else regSessionTimeout.set(element.domain, 15*60) //Seconds
  });

  if('mem' == process.env.STORAGE_TYPE){
    registeredRps.forEach(element => {
      if(!database.get(element)) database.set(element, new Map());      
    });
    for (const key of database.keys()) {
      if( 0 > registeredRps.indexOf(key) ){
        database.delete(key)
      }
    }
  }else if('mysql' == process.env.STORAGE_TYPE){
    setRps(registeredRps);
  }

}
  
function getDomainJSON(domain){
  var rtn = null
  domains_conf = JSON.parse(fs.readFileSync(DOMAIN_JSON_FN, 'utf8'));

  for(let i = 0 ; i < domains_conf.domains.length ; i++){
    if(domains_conf.domains[i].domain == domain){
      rtn = domains_conf.domains[i]
      break
    }
  }
  
  return rtn
}

async function AppController(request, response) {
  const url = new URL(request.url, `https://${request.headers.host}`)

  if(request.method === 'GET') {
    let html=""
    try{
        /*let real_path;
        if(url.pathname === '/')real_path='fido2.html'
        else real_path = url.pathname
        html = require('fs').readFileSync('views/'+real_path);*/
        html = require('fs').readFileSync('views/'+url.pathname);
    }catch(ex){
        html=ex.message
    }
    response.writeHead(200, {'Content-Type': 'text/html'});
    response.end(html);
  } else if(request.method === 'OPTIONS') {
    try{
      response.setHeader("Access-Control-Allow-Origin", "*");
      response.setHeader("Access-Control-Allow-Methods", "POST");
      response.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, access_token");
      response.setHeader("Access-Control-Allow-Credentials", "true");
      response.end('OK');
      return
    }catch(ex){
      logger.error("EX: " + ex.message + ";" + ex.stack)
      let rtn={};
      rtn.status ='failed',
      rtn.errorMessage = 'SvrErr999:Exception:' + ex.message
      response.end(JSON.stringify(rtn));
    }
  } else if(request.method === 'POST') {
    try{
      var req_origin = FIDO_ORIGIN, req_host
      if(request.headers['referer']){
        const remoteURL = new URL(request.headers['referer'])
        req_host = remoteURL.hostname
        req_origin = remoteURL.protocol + "//" + req_host        
      }

      let real_path;

      response.setHeader("Access-Control-Allow-Origin", "*");
      response.setHeader("Access-Control-Allow-Methods", "POST");
      response.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, access_token");
      response.setHeader("Access-Control-Allow-Credentials", "true");
      
      if(url.pathname == '/assertion/options'){
        const body = await loadJsonBody(request)
    
        let username = body.username;
    
        //Client-side discoverable Credential does not pass username

        let rpId=checkRpId(body, req_host, response)
        if(null==rpId)return

        let user = await getUserData(rpId, username)
        if(username && username.length > 0 && (!user || !user.registered)) {
          response.end(JSON.stringify({
            'status': 'failed',
            'errorMessage': `SvrErr105:Username ${username} does not exist!`
          }));
          return
        }
    
        let fido2Lib =  getFido2Lib(rpId, body)
        let authnOptions = await fido2Lib.assertionOptions(body);
        /* dqj: set by lib 
        if(!username){//Try discoverable 
          authnOptions["mediation"] = "conditional"
        }*/
        let challengeTxt = uuidv4()
        let challengeBase64 = base64url.encode(challengeTxt) //To fit to the challenge of CollectedClientData
        authnOptions.challenge = challengeBase64 //Array.from(new TextEncoder().encode(challengeTxt))
    
        let allowCredentials = [];
        if( username && username.length > 0 ){
          let attestations = await getAttestationData(rpId, username)
          for(let authr of attestations) {
            allowCredentials.push({
              type: 'public-key',
              id: base64url.encode(authr.credId), //Array.from(new Uint8Array(authr.credId)),
              transports: ['internal', 'hybrid', 'usb', 'nfc', 'ble']// can be overrided by client
            })
          }
          authnOptions.allowCredentials = allowCredentials;

          if(passkeySync.get(rpId)){
            authnOptions.extensions.passkeySync = true
            authnOptions.extensions.deviceBinded = false
          }else if(deviceBindedKeys.get(rpId)){
            authnOptions.extensions.deviceBinded = true
          }

          //console.log(authnOptions);
          logger.debug(authnOptions);
        }
            
        sessions[challengeBase64] = {
          'challenge': authnOptions.challenge,
          'username': username?username:"",
          'fido2lib': fido2Lib,
        };

        authnOptions.status = 'ok';
        authnOptions.errorMessage = '';
    
        response.end(JSON.stringify(authnOptions));
      }else if(url.pathname == '/assertion/result'){
        const body = await loadJsonBody(request)

        const clientData = JSON.parse(stringfy(body.response.clientDataJSON))
        
        if(!body.response.authenticatorData){
          let rtn = {
            'status': 'failed',
            'errorMessage': 'SvrErr115:authenticatorData is not found!'
          }
          response.end(JSON.stringify(rtn));
          return
        } else if(!utils.isBase64Url(body.response.authenticatorData)){
          let rtn = {
            'status': 'failed',
            'errorMessage': 'SvrErr116:authenticatorData is not base64 url encoded!'
          }
          response.end(JSON.stringify(rtn));
          return
        }

        if(!body.response.signature){
          let rtn = {
            'status': 'failed',
            'errorMessage': 'SvrErr117:signature is not found!'
          }
          response.end(JSON.stringify(rtn));
          return
        } else if(!utils.isBase64Url(body.response.signature)){
          let rtn = {
            'status': 'failed',
            'errorMessage': 'SvrErr118:signature is not base64 url encoded!'
          }
          response.end(JSON.stringify(rtn));
          return
        }

        body.response.authenticatorData = new Uint8Array(base64url.toBuffer(body.response.authenticatorData)).buffer; //bufferKeepBase64(body.response.authenticatorData)
        body.response.signature = new Uint8Array(base64url.toBuffer(body.response.signature)).buffer; //bufferKeepBase64((body.response.signature))
        body.response.userHandle = base64url.toBuffer(body.response.userHandle); //new TextDecoder().decode(new Uint8Array(base64url.toBuffer(body.response.userHandle)).buffer)   
        body.response.userHandle = stringfy(body.response.userHandle)//new TextDecoder().decode(body.response.userHandle)
        body.response.clientDataJSON = new Uint8Array(base64url.toBuffer(body.response.clientDataJSON)).buffer; //bufferKeepBase64(body.response.clientDataJSON)
    
        let attestation = null;

        let chkReq = checkResultRequest(body)
        if(0 < Object.keys(chkReq).length){
          response.end(JSON.stringify(chkReq));
          return;
        }

        //let debugId=new Uint8Array(base64url.toBuffer(body.id)).buffer//for debug
        var reqId
        if( body.rawId ){
          reqId = new Uint8Array(body.rawId);
        }
        if( !reqId || reqId.length == 0){
          reqId = new Uint8Array(base64url.toBuffer(body.id))
        }          
        body.rawId = reqId.buffer;

        var challenge = stringfy(clientData.challenge)
        if(!utils.isBase64(challenge))challenge = clientData.challenge //Client may encodebase64 the challenge

        var realUsername;
        var attestations;
        if(sessions[challenge].username && sessions[challenge].username.length > 0){          
          realUsername = sessions[challenge].username
        }else {
          realUsername = await discoverUserName(reqId)//Client-side discoverable Credential process
        }

        if(null==sessions[challenge].fido2lib)return

        if(realUsername){
          attestations = await getAttestationData(sessions[challenge].fido2lib.config.rpId, realUsername)
          for( let i = 0 ; attestations && i < attestations.length ; i++ ){          
            let dbId = attestations[i].credId         
            if (dbId.byteLength == reqId.byteLength && equlsArrayBuffer(reqId, dbId)) {
              attestation = attestations[i];
              break;           
            }
          }
        }
        
        if( !attestation ){
          let rtn = {
            'status': 'failed',
            'errorMessage': 'SvrErr104:key is not found!'
          }
          if(realUsername){
            await recordUserAction(sessions[challenge].fido2lib.config.rpId, realUsername, 1, challenge, "SvrErr104")
          }
          response.end(JSON.stringify(rtn));
          return
        }
        
        const cur_session = sessions[challenge]
        delete sessions[challenge]

        let user = await getUserData(cur_session.fido2lib.config.rpId, realUsername)
        let assertionExpectations = {
          challenge: cur_session.challenge,
          origin: req_origin, //FIDO_ORIGIN,
          rpId: cur_session.fido2lib.config.rpId,
          factor: "either",
          publicKey: attestation.publickey,
          prevCounter: attestation.counter,
          userHandle: user.id          
        };

        body.userVerification = cur_session.fido2lib.config.authenticatorUserVerification
        
        let authnResult = await cur_session.fido2lib.assertionResult(body, assertionExpectations);
        //console.log(authnResult);
        logger.debug(authnResult)
    
        let rtn='';
        if(authnResult.audit.complete) {
          const unique_device_id = 
            authnResult.authnrData.get('extensions') ? (authnResult.authnrData.get('extensions').get('dfido2_device_unique_id') ? authnResult.authnrData.get('extensions').get('dfido2_device_unique_id') : null) : null;
          if(deviceBindedKeys.get(cur_session.fido2lib.config.rpId) && null==unique_device_id ){
            rtn = {
              'status': 'failed',
              'errorMessage': 'SvrErr106:Unique device id is null!'
            }
            await recordUserAction(cur_session.fido2lib.config.rpId, realUsername, 1, challenge, "SvrErr106")
          } else {
            if(deviceBindedKeys.get(cur_session.fido2lib.config.rpId) && null != unique_device_id && 
              attestation.unique_device_id !== unique_device_id){
            //!bindedDeviceKey(cur_session.fido2lib.config.rpId, cur_session.username, attestation.publickey, unique_device_id)){
              rtn = {
                'status': 'failed',
                'errorMessage': 'SvrErr102:Cannot auth with a unique device bound key from a different device!'
              }
              await recordUserAction(cur_session.fido2lib.config.rpId, realUsername, 1, challenge, "SvrErr102")
            }else{              
              const session_id = await generateUserSession(cur_session.fido2lib.config.rpId, realUsername)

              attestation.counter = authnResult.authnrData.get('counter');    
            
              rtn = {
                status: 'ok',
                credId: body.id,
                counter: attestation.counter,
                username: realUsername,
                session: session_id,
                errorMessage: ''
              }
            }
          }          
        } else {
          rtn = {
            'status': 'failed',
            'errorMessage': 'SvrErr103:Can not authenticate signature!'
          }
          await recordUserAction(cur_session.fido2lib.config.rpId, realUsername, 1, challenge, "SvrErr103")
        }
        
        await recordUserAction(cur_session.fido2lib.config.rpId, realUsername, 1, challenge)
        response.end(JSON.stringify(rtn));
      }else if(url.pathname === '/attestation/options'){
        const body = await loadJsonBody(request)

        let rpId=checkRpId(body, req_host, response)
        if(null==rpId)return

        let username = body.username;

        let userid;
        let user = await getUserData(rpId, username)
        if(user) {
          userid = user.id;
        }else{
          userid = uuidv4();
        }

        let fido2Lib =  getFido2Lib(rpId, body)
        let registrationOptions = await fido2Lib.attestationOptions();
        let challengeTxt = uuidv4()
        let challengeBase64 = base64url.encode(challengeTxt) //To fit to the challenge of CollectedClientData
        registrationOptions.challenge = challengeBase64//Array.from(new TextEncoder().encode(challengeTxt)) //base64url.encode(uuidv4())//use challenge as session id

        registrationOptions.authenticatorSelection = body.authenticatorSelection

        //Prevent register same authenticator
        if(user){
          user.attestation = await getAttestationData(rpId, username)
          let excludeCredentials = [];
          for(let authr of user.attestation) {
            excludeCredentials.push({
                type: 'public-key',
                id: base64url.encode(authr.credId), //Array.from(new Uint8Array(authr.credId)),
                transports: ['internal', 'hybrid', 'usb', 'nfc', 'ble']
              })
          }
          if(excludeCredentials.length > 0)registrationOptions.excludeCredentials = excludeCredentials

          //console.log("excludeCredentials:" + username + " size:" + excludeCredentials.length);
        }        

        registrationOptions.user.id = base64url.encode(userid);
        registrationOptions.user.name = username;
        registrationOptions.user.displayName = body.displayName?body.displayName:username;

        if(body.attestation)registrationOptions.attestation = body.attestation
        else if(fido2Lib.config.attestation){
          registrationOptions.attestation = fido2Lib.config.attestation
        }

        if(passkeySync.get(rpId)){
          registrationOptions.extensions.passkeySync = true
          registrationOptions.extensions.deviceBinded = false

          registrationOptions.pubKeyCredParams = [ 
            {type: "public-key", alg: -7},
            {type: "public-key", alg: -257}
          ];
        }else if(deviceBindedKeys.get(rpId)){
          registrationOptions.extensions.deviceBinded = true
        }

        //console.log(registrationOptions);
        logger.debug(registrationOptions);

        if(!user){
          await putUserData(rpId, username, userid, registrationOptions.user.displayName, false);
        }        

        sessions[challengeBase64] = {
          'challenge': registrationOptions.challenge,
          'username': username,
          'fido2lib': fido2Lib
        };

        registrationOptions.status = 'ok';
        registrationOptions.errorMessage = '';

        response.end(JSON.stringify(registrationOptions));

      }else if( url.pathname == '/attestation/result'){
        const body = await loadJsonBody(request)

        let rtn={};

        let chkReq = checkResultRequest(body)
        if(0 < Object.keys(chkReq).length){
          response.end(JSON.stringify(chkReq));
          return;
        }

        const clientData = JSON.parse(stringfy(body.response.clientDataJSON))        
        
        //For debug
        /*const tpAtt = typeof body.response.attestationObject
        const attobj=new Buffer.from(body.response.attestationObject)
        var ab = new ArrayBuffer(attobj.length);
        var view = new Uint8Array(ab);
        for (var i = 0; i < attobj.length; ++i) {
            view[i] = attobj[i];
        }*/
        //End of debug

        body.rawId = new Uint8Array(base64url.toBuffer(body.rawId)).buffer; //bufferKeepBase64(body.rawId); 
        body.response.attestationObject = new Uint8Array(base64url.toBuffer(body.response.attestationObject)).buffer//bufferKeepBase64(body.response.attestationObject)        
        body.response.clientDataJSON = new Uint8Array(base64url.toBuffer(body.response.clientDataJSON)).buffer; //bufferKeepBase64(body.response.clientDataJSON)
        
        //const attestationObject = parser.parseAttestationObject(body.response.attestationObject) //JSON.parse(stringfy(body.response.attestationObject))

        var challenge = stringfy(clientData.challenge)
        if(!utils.isBase64(challenge))challenge = clientData.challenge //Client may encodebase64 the challenge
        const cur_session = sessions[challenge]
        delete sessions[challenge]

        //console.log("/attestation/result:" + cur_session.username)

        if(null==cur_session.fido2lib)return

        let attestationExpectations = {
            challenge: cur_session.challenge,
            origin: req_origin, //FIDO_ORIGIN,
            rpId: cur_session.fido2lib.config.rpId,
            factor: "either"
        };

        var regResult
        try{
          regResult = await cur_session.fido2lib.attestationResult(body, attestationExpectations);
        }catch(exp){
          //console.log("/attestation/result exp:" + cur_session.username + " msg="+exp.message)
          throw exp
        }
        
        logger.debug(regResult);        

        const credId = regResult.authnrData.get('credId')

        const aaguidData = regResult.authnrData.get('aaguid')
        const aaguid = buf2hex(aaguidData)
        //const aaguidtxt = buf2text(aaguidData) // Buffer.from(aaguid, 'hex').toString('utf-8'); //String.fromCharCode.apply("", new Uint8Array(aaguidData))

        if(cur_session.fido2lib.config.attestation == "enterprise"){
          const guids = enterpriseAaguids.get(cur_session.fido2lib.config.rpId)
          if(!guids || !guids.includes(aaguid) ){
            rtn.status ='failed',
            rtn.errorMessage = 'SvrErr101:Unregistered enterprise authenticator aaguid!'
          }
          await recordUserAction(cur_session.fido2lib.config.rpId, cur_session.username, 0, challenge, "SvrErr101")
        }

        const unique_device_id = 
          regResult.authnrData.get('extensions') ? (regResult.authnrData.get('extensions').get('dfido2_device_unique_id') ? regResult.authnrData.get('extensions').get('dfido2_device_unique_id') : null) : null;

        if(deviceBindedKeys.get(cur_session.fido2lib.config.rpId) && null==unique_device_id ){
          rtn = {
            'status': 'failed',
            'errorMessage': 'SvrErr106:Unique device id is null!'
          }
          await recordUserAction(cur_session.fido2lib.config.rpId, cur_session.username, 0, challenge, "SvrErr106")
        } else {
          //console.log("before pushAttestation status:" + JSON.stringify(rtn))
          if(0 == Object.keys(rtn).length){
            //console.log("before pushAttestation call:" + cur_session.username)
            const counter = regResult.authnrData.get('counter');
            await pushAttestation(cur_session.fido2lib.config.rpId, cur_session.username, 
              regResult.authnrData.get('credentialPublicKeyPem'), counter, regResult.authnrData.get('fmt'),
              new Uint8Array(credId), aaguid, unique_device_id, request.headers['user-agent']?request.headers['user-agent']:"");
            
            mapCredidUsername[new Uint8Array(credId)]=cur_session.username;
            
            if(regResult.audit.complete) {
              await setRegistered(cur_session.fido2lib.config.rpId, cur_session.username, true)         
        
              const session_id = await generateUserSession(cur_session.fido2lib.config.rpId, cur_session.username)

              rtn.status = 'ok',
              rtn.counter = counter
              rtn.credId = Array.from(new Uint8Array(regResult.authnrData.get('credId')))
              rtn.errorMessage = '';
              rtn.session = session_id;
            } else {
              rtn.status ='failed',
              rtn.errorMessage = 'SvrErr103:Can not authenticate signature!'
              await recordUserAction(cur_session.fido2lib.config.rpId, cur_session.username, 0, challenge, "SvrErr103")
            }             
          }
        }

        //console.log("result end:" + cur_session.username + " rtn=" + JSON.stringify(rtn))

        await recordUserAction(cur_session.fido2lib.config.rpId, cur_session.username, 0, challenge)
        response.end(JSON.stringify(rtn));
      }
      // ====== User Management methods ======
      else if( url.pathname.startsWith('/usr/') ){
        const body = await loadJsonBody(request)

        let rpId=checkRpId(body, req_host, response)
        if(null==rpId)return

        const validsession = body.session && await checkUserSession(rpId, body.session)

        if( url.pathname == '/usr/validsession' ){//valid user's session
          var rtn = {
            status:validsession?"ok":"fail"
          }
          response.end(JSON.stringify(rtn));
          return
        }

        if(!validsession){
          logger.warn('Somebody tried to access usr path:('+request.socket.remoteAddress+') without user session.');
          var rtn = {
            errorMessage:"SvrErr119: No user session!"
          }
          response.end(JSON.stringify(rtn));
          return
        }

        if( url.pathname == '/usr/dvs/lst' ){//list user's devices
          const lst = await listUserDevices(rpId, body.session)
          var rtn = {
            session:body.session,
            devices:lst,
            status:"ok"
          }
          response.end(JSON.stringify(rtn));
        }else if( url.pathname == '/usr/dvs/rm' ){//remove user's devices
          const del = await delUserDevices(rpId, body.session, body.device_id)
          var rtn = {
            session:body.session,
            status:del>=0?"ok":"fail",
            remain_count:del
          }
          response.end(JSON.stringify(rtn));
        }
      }
      // ====== System Management methods ======
      // There are json examples in examples folder
      else if( url.pathname.startsWith('/mng/') ){
        const body = await loadJsonBody(request)
        if(body.MNG_TOKEN && body.MNG_TOKEN==process.env.MNG_TOKEN){
          if( url.pathname == '/mng/domain/conf' ){
            //backup json file
            const backupFileName =  DOMAIN_JSON_FN + Date.now();
            fs.copyFileSync(DOMAIN_JSON_FN, backupFileName);
            logger.info('Backuped ' + DOMAIN_JSON_FN + ' to ' + backupFileName);

            domains_conf.backupfile = backupFileName;

            if(body.del){//Del domains first
              body.del.forEach(element => {
                for (let i = 0; i < domains_conf.domains.length; ++i) {
                  if( element == domains_conf.domains[i].domain){
                    domains_conf.domains.splice(i, 1);
                    i--;
                  }
                }
              });
            }

            if(body.set){//Set domains
              body.set.forEach(element => {
                let i = 0
                for (; i < domains_conf.domains.length; ++i) {
                  if( element.domain == domains_conf.domains[i].domain){
                    domains_conf.domains[i]=element;
                    break;
                  }
                }
                if(i==domains_conf.domains.length){
                  domains_conf.domains.push(element);
                }
              });
            }

            //Write new json
            fs.unlinkSync(DOMAIN_JSON_FN);
            fs.writeFileSync(DOMAIN_JSON_FN, JSON.stringify(domains_conf), 'utf8');
            logger.info('Created new ' + DOMAIN_JSON_FN);

            loadDomains();
            
            const rtn = {status:'OK'}
            response.end(JSON.stringify(rtn));
          } else if( url.pathname == '/mng/domain/rollback' ){
            var rtn
            if(domains_conf.backupfile && fs.existsSync(domains_conf.backupfile)){
              fs.unlinkSync(DOMAIN_JSON_FN);
              fs.copyFileSync(domains_conf.backupfile, DOMAIN_JSON_FN);
              fs.unlinkSync(domains_conf.backupfile);

              loadDomains();

              rtn = {status:'OK'}
            }else{
              rtn = {status:'fail'}
              logger.warn('Backup file does not exist:' + (domains_conf.backupFileName?domains_conf.backupFileName:'null'));
            }
            
            response.end(JSON.stringify(rtn));
          } else if( url.pathname == '/mng/domain/get' ){
            var rtn = {status:'fail'}
            if(body.domain){
              let conf = getDomainJSON(body.domain)
              if(conf){
                rtn = conf
                rtn.status='OK'
              }              
            }            
            response.end(JSON.stringify(rtn));
          } else if( url.pathname == '/mng/domain/data' ){
            var rtn = {status:'fail'}
            if(body.domains && null!=body.start && null!=body.end){
              rtn = await getDomainData(body.domains, body.start, body.end)
              rtn.status='OK'
            }            
            response.end(JSON.stringify(rtn));
          } else if( url.pathname == '/mng/action/data' ){
            var rtn = {status:'fail'}
            if(body.domains && null!=body.start && null!=body.end){
              rtn = await getActionData(body.domains, body.start, body.end)
              rtn.status='OK'
            }            
            response.end(JSON.stringify(rtn));
          } else if( url.pathname == '/mng/data/users' ){
            var rtn = {status:'fail'}
            if(body.domains){
              rtn = await listUsers(body.domains, body.start?body.start:0, body.end?body.end:Number.MAX_SAFE_INTEGER, 
                    body.search, body.last_created, body.limit?body.limit:20);
              rtn.status='OK'
            }
            response.end(JSON.stringify(rtn));
          } else if( url.pathname == '/mng/data/actions' ){
            var rtn = {status:'fail'}
            if(body.domains){
              rtn = await listActions(body.domains, body.start?body.start:0, body.end?body.end:Number.MAX_SAFE_INTEGER, 
                    body.search, body.last_created, body.fail_only, body.limit?body.limit:20);
              rtn.status='OK'
            }
            response.end(JSON.stringify(rtn));
          } else if( url.pathname == '/mng/user/delacc' ){
            var rtn = {status:'fail'}
            if(body.domains && body.user_id){
              rtn = await delUser(body.domains, body.user_id);
              rtn.status='OK'
            }            
            response.end(JSON.stringify(rtn));
          } else if( url.pathname == '/mng/user/deldvc' ){
            var rtn = {status:'fail'}
            if(body.domains && body.attest_id){
              rtn = await delDevice(body.domains, body.attest_id);
            }
            rtn.status='OK'
            response.end(JSON.stringify(rtn));          
          } else if( url.pathname == '/mng/user/regsession' ){
            var rtn = {status:'fail'}
            if(body.username){
              rtn.session_id = await generateRegSession(body.username);
              rtn.status='OK'
            }
            response.end(JSON.stringify(rtn));         
          }
        } else{
          logger.warn('Somebody tried to access mng path:('+request.socket.remoteAddress+') with token='+
              (body.MNG_TOKEN?body.MNG_TOKEN:'null'));
          response.end("");
        }        
      }
      // ====== Registration method ======
      else if( url.pathname.startsWith('/reg/username') ){
        const body = await loadJsonBody(request)
        if(body.session_id ){
          let rpId=checkRpId(body, req_host, response)
          if(null==rpId)return

          let unm = await getRegSessionUsername(body.session_id)
          if(unm){
            response.end(JSON.stringify({
                'status': 'ok',
                'username': unm
              }));
          }else{
            response.end(JSON.stringify({
              'status': 'failed'
            }));
          }
      }
    }
    }catch(ex){      
      //console.log("EX: " + ex.message)
      logger.error("EX: " + ex.message  + ";" + ex.stack)
      let rtn={};
      rtn.status ='failed',
      rtn.errorMessage = 'SvrErr999:Exception:' + ex.message
      response.end(JSON.stringify(rtn));
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

function checkResultRequest(jsonBody){
  var rtn = {};
  if(!jsonBody.id){
    rtn = {
      'status': 'failed',
      'errorMessage': 'SvrErr107:No ID field in the body of /attestation/result request!'
    }
  }else if(typeof jsonBody.id !== 'string'){
    rtn = {
      'status': 'failed',
      'errorMessage': 'SvrErr112:The ID field is not a DOMString in the body of /attestation/result request!'
    }
  }else if(!utils.isBase64Url(jsonBody.id)){
    rtn = {
      'status': 'failed',
      'errorMessage': 'SvrErr108:ID field is not Base64Url encoded in the body of /attestation/result request!'
    }
  }else if(!jsonBody.type){
    rtn = {
      'status': 'failed',
      'errorMessage': 'SvrErr109:No TYPE field in the body of /attestation/result request!'
    }
  }else if(typeof jsonBody.type !== 'string'){
    rtn = {
      'status': 'failed',
      'errorMessage': 'SvrErr110:The TYPE field is not a DOMString in the body of /attestation/result request!'
    }
  }else if(jsonBody.type !== 'public-key'){
    rtn = {
      'status': 'failed',
      'errorMessage': 'SvrErr111:The TYPE field is not public-key in the body of /attestation/result request!'
    }
  }
  return rtn;
}

function isBase64(str) {  
  try {
    if (str ==='' || str.trim() ===''){ return false; }
    let ins = str.replace(/\-/g, "+").replace(/_/g, "/")
    var ss= atob(ins)
    ss=btoa(ss).replace(/\+/g, "-").replace(/\//g, "_").replaceAll("=", "")
    return ss == str;
    //return str.match(/^([A-Za-z0-9+/])*/g) || str.match(/^([A-Za-z0-9-_])*/g)
  } catch (err) {
    return false;
  }
}

function bufferKeepBase64(input) {
  if(isBase64(input)) return input;
  else if(typeof input == "string")return Uint8Array.from(new TextEncoder().encode(input)).buffer
  else return new Uint8Array(input).buffer;          
}

function stringfy(input) {
  if(isBase64(input)){
    const cda=new Uint8Array(base64url.toBuffer(input))
    const cltdatatxt = String.fromCharCode.apply("", cda)
    //console.log('clientDataJSON:'); //console.log(cltdatatxt)
    return cltdatatxt;
  }else if(typeof input == "string") return input
  else{
    return new TextDecoder().decode(new Uint8Array(input)) //new TextEncoder().encode(input)
  }
}

function getFido2Lib(rpId, reqBody){
  let rp = DEFAULT_FIDO_RPID
  if(rpId && registeredRps.includes(rpId)){
    rp = rpId
  }

  var opts = {
    rpId: rp,
    timeout: processTimeout.get(rpId)
  }

  if(enterpriseRps.includes(rp)){
    opts.attestation = "enterprise"
  }

  if(null!=reqBody){
    if(reqBody.userVerification){//}.authenticatorSelection){
      opts.authenticatorUserVerification=reqBody.userVerification
    }
  }

  let f2lib = require('./fido2-node-lib/main'); //new Fido2Lib(opts);

  return new f2lib(opts)
}

function checkRpId(reqBody, req_host, response){
  var real_rp_id
  if(reqBody.rp && reqBody.rp.id){
    real_rp_id = reqBody.rp.id
  } else if(req_host){
    real_rp_id = req_host
  } else real_rp_id = DEFAULT_FIDO_RPID

  logger.debug('checkRpId real_rp_id=' + real_rp_id)

  if(registeredRps.includes(real_rp_id)){
    return real_rp_id
  }else{
    response.end(
      JSON.stringify({
        'status': 'failed',
        'errorMessage': `No exist rp.id: ${real_rp_id}`
      })
    );
    return null
  }
}

async function loadJsonBody(request){
  const buffers = [];

  for await (const chunk of request) {
    buffers.push(chunk);
  }

  const bodytxt = Buffer.concat(buffers).toString();

  const body = JSON.parse(bodytxt);
  logger.debug(body);

  return body;
}

//Storage methods
async function checkUserSession(rpId, session_id){
  var rtn = false;
  activeUserSession(rpId, session_id);
  if('mem'==process.env.STORAGE_TYPE){
    rtn = null != user_sessions.get(session_id)
  }else if('mysql'==process.env.STORAGE_TYPE){
    const connection = await new Promise((resolve, reject) => {
      mysql_pool.getConnection((error, connection) => {
        if (error) reject(error)
        resolve(connection)
      })
    })

    try {
      const results = await new Promise((resolve, reject) => {
        connection.query('SELECT * from user_sessions where session_id=? and TIMESTAMPDIFF(SECOND, created, NOW()) < ? and TIMESTAMPDIFF(SECOND, actived, NOW()) < ?', 
            [session_id, userSessionHardTimeout.get(rpId), userSessionActiveTimeout.get(rpId)],
            (error, results) => {
              if (error) reject(error)
              resolve(results)
            })
      })
      rtn = 0<results.length
    }catch (err) {      
      logger.error('DB err:'+err)
    } finally {
      connection.release()
    }
  }else{
    logger.error('Unknown process.env.STORAGE_TYPE:' + process.env.STORAGE_TYPE);
  }
  return rtn;
}

async function getDomainData(domains, start, end){
  var rtn = {};
  if('mysql'==process.env.STORAGE_TYPE){
    const connection = await new Promise((resolve, reject) => {
      mysql_pool.getConnection((error, connection) => {
        if (error) reject(error)
        resolve(connection)
      })
    })

    try {
      var domains_where = ' r.rp_domain in ("' + domains.map(d => d).join('","') + '") and '

      var results = await new Promise((resolve, reject) => {
        connection.query('SELECT rp_id from registered_rps r '+
              'where '+ domains_where +' deleted is null ', 
            [],
            (error, results) => {
              if (error) reject(error)
              resolve(results)
            })
      })

      var rpids_where = ' r.rp_id in (' + results.map(d => d.rp_id).join(',') + ') '
      results = await new Promise((resolve, reject) => {
        connection.query('SELECT count(*) as allc from registered_users u, registered_rps r '+
              'where '+ rpids_where +' and r.rp_id=u.rp_id and u.registered=true and r.deleted is null and u.deleted is null ', 
            [start, end],
            (error, results) => {
              if (error) reject(error)
              resolve(results)
            })
      })
      rtn.total_users = results.length>0?results[0]['allc']:0;

      results = await new Promise((resolve, reject) => {
        connection.query('SELECT count(DISTINCT a.user_id) as actv from user_actions a, registered_users r '+
              'where '+ rpids_where +' and r.user_id=a.user_id and r.registered=true and r.deleted is null and a.created between ? and ? ', 
            [start, end],
            (error, results) => {
              if (error) reject(error)
              resolve(results)
            })
      })
      rtn.active_users = results.length>0?results[0]['actv']:0;

      results = await new Promise((resolve, reject) => {
        connection.query('SELECT count(*) as auth from user_actions a, registered_users r '+
              'where '+ rpids_where +' and r.user_id=a.user_id and action_type=1 and r.registered=true and r.deleted is null and a.created between ? and ? ', 
            [start, end],
            (error, results) => {
              if (error) reject(error)
              resolve(results)
            })
      })
      rtn.total_auth = results.length>0?results[0]['auth']:0;

      results = await new Promise((resolve, reject) => {
        connection.query('SELECT count(*) as auth from user_actions a, registered_users r '+
              'where '+ rpids_where +' and r.user_id=a.user_id and action_type=1 and r.registered=true and error<>"" and r.deleted is null and a.created between ? and ? ', 
            [start, end],
            (error, results) => {
              if (error) reject(error)
              resolve(results)
            })
      })
      rtn.fail_auth = results.length>0?results[0]['auth']:0;
    }catch (err) {      
      logger.error('DB err:'+err)
    } finally {
      connection.release()
    }
  }else{
    logger.error('Unsupport getDomainData for process.env.STORAGE_TYPE:' + process.env.STORAGE_TYPE);
  }
  return rtn;
}

async function listUsers(domains, start, end, search = null, last_created = null, limit = 20){
  var rtn = {};
  if('mysql'==process.env.STORAGE_TYPE){
    const connection = await new Promise((resolve, reject) => {
      mysql_pool.getConnection((error, connection) => {
        if (error) reject(error)
        resolve(connection)
      })
    })

    try {
      var domains_where = ' r.rp_domain in ("' + domains.map(d => d).join('","') + '") and '

      var results = await new Promise((resolve, reject) => {
        connection.query('SELECT rp_id, rp_domain from registered_rps r '+
              'where '+ domains_where +' deleted is null ', 
            [],
            (error, results) => {
              if (error) reject(error)
              resolve(results)
            })
      })

      //build hashmap of rp_domain and rp_id
      var rp_domain_rp_id = {}
      for (const row of results) {
        rp_domain_rp_id[row.rp_id] = row.rp_domain
      }

      var rpids_where = ' rp_id in (' + results.map(d => d.rp_id).join(',') + ') '
      var search_where = search && search.length >0 ? ' username like "%'+search+'%" ':' 1=1 '
      var last_created_where = last_created && last_created.length >0 ? ' created < "'+last_created+'" ':' 1=1 '
      results = await new Promise((resolve, reject) => {
        connection.query('SELECT user_id, rp_id, username, displayname, created from registered_users '+
              'where '+ rpids_where + ' and ' + search_where + ' and ' + last_created_where + 
              ' and registered=true and deleted is null and created between ? and ? order by created desc limit ' + limit, 
            [start, end],
            (error, results) => {
              if (error) reject(error)
              resolve(results)
            })
      })

      //list user's devices
      var last_created = null;
      for (const row of results) {
        const devices = await new Promise((resolve, reject) => {
          connection.query('SELECT attest_id, aaguid, user_agent, created from attestations '+
                'where user_id=? and deleted is null order by created desc',
              [row.user_id],
              (error, results) => {
                if (error) reject(error)
                resolve(results)
              })
        })
        if(0<devices.length){
          var devs = []
          for(let elm of devices) {  
            const meta_entry = await mds3_client.findByAAGUID(elm.aaguid)            
            devs.push({
              device_id: elm.attest_id,
              userAgent: elm.user_agent?elm.user_agent:"",
              desc: meta_entry && meta_entry.metadataStatement && meta_entry.metadataStatement.description ? 
                  meta_entry.metadataStatement.description:"",
              registered_time: elm.created
            })
          }
          row.devices = devs
        }
        row.domain = rp_domain_rp_id[row.rp_id]
        last_created = row.created
      }
      rtn.users = results      
      rtn.last_created = last_created
    }catch (err) {      
      logger.error('DB err:'+err)
    } finally {
      connection.release()
    }
  }else{
    logger.error('Unsupport listUsers for process.env.STORAGE_TYPE:' + process.env.STORAGE_TYPE);
  }
  return rtn;
}

async function getActionData(domains, start, end){
  var rtn = {};
  if('mysql'==process.env.STORAGE_TYPE){
    const connection = await new Promise((resolve, reject) => {
      mysql_pool.getConnection((error, connection) => {
        if (error) reject(error)
        resolve(connection)
      })
    })

    try {
      var domains_where = ' r.rp_domain in ("' + domains.map(d => d).join('","') + '") and '

      var results = await new Promise((resolve, reject) => {
        connection.query('SELECT rp_id from registered_rps r '+
              'where '+ domains_where +' deleted is null ', 
            [],
            (error, results) => {
              if (error) reject(error)
              resolve(results)
            })
      })

      var rpids_where = ' r.rp_id in (' + results.map(d => d.rp_id).join(',') + ') '      

      results = await new Promise((resolve, reject) => {
        connection.query('SELECT count(*) as auth from user_actions a, registered_users r '+
              'where '+ rpids_where +' and r.user_id=a.user_id and action_type=1 and r.registered=true and r.deleted is null and a.created between ? and ? ', 
            [start, end],
            (error, results) => {
              if (error) reject(error)
              resolve(results)
            })
      })
      rtn.total_auth = results.length>0?results[0]['auth']:0;

      results = await new Promise((resolve, reject) => {
        connection.query('SELECT count(*) as auth from user_actions a, registered_users r '+
              'where '+ rpids_where +' and r.user_id=a.user_id and action_type=0 and r.registered=true and r.deleted is null and a.created between ? and ? ', 
            [start, end],
            (error, results) => {
              if (error) reject(error)
              resolve(results)
            })
      })
      rtn.total_reg = results.length>0?results[0]['auth']:0;

      results = await new Promise((resolve, reject) => {
        connection.query('SELECT count(*) as auth from user_actions a, registered_users r '+
              'where '+ rpids_where +' and r.user_id=a.user_id and action_type=1 and r.registered=true and error<>"" and r.deleted is null and a.created between ? and ? ', 
            [start, end],
            (error, results) => {
              if (error) reject(error)
              resolve(results)
            })
      })
      rtn.total_auth_fail = results.length>0?results[0]['auth']:0;

      results = await new Promise((resolve, reject) => {
        connection.query('SELECT count(*) as auth from user_actions a, registered_users r '+
              'where '+ rpids_where +' and r.user_id=a.user_id and action_type=0 and r.registered=true and error<>"" and r.deleted is null and a.created between ? and ? ', 
            [start, end],
            (error, results) => {
              if (error) reject(error)
              resolve(results)
            })
      })
      rtn.total_reg_fail = results.length>0?results[0]['auth']:0;

    }catch (err) {      
      logger.error('DB err:'+err)
    } finally {
      connection.release()
    }
  }else{
    logger.error('Unsupport getDomainData for process.env.STORAGE_TYPE:' + process.env.STORAGE_TYPE);
  }
  return rtn;
}

async function listActions(domains, start, end, search = null, last_created = null, fail_only = false, limit = 20){
  var rtn = {};
  if('mysql'==process.env.STORAGE_TYPE){
    const connection = await new Promise((resolve, reject) => {
      mysql_pool.getConnection((error, connection) => {
        if (error) reject(error)
        resolve(connection)
      })
    })

    try {
      var domains_where = ' r.rp_domain in ("' + domains.map(d => d).join('","') + '") and '

      var results = await new Promise((resolve, reject) => {
        connection.query('SELECT rp_id, rp_domain from registered_rps r '+
              'where '+ domains_where +' deleted is null ', 
            [],
            (error, results) => {
              if (error) reject(error)
              resolve(results)
            })
      })

      //build hashmap of rp_domain and rp_id
      var rp_domain_rp_id = {}
      for (const row of results) {
        rp_domain_rp_id[row.rp_id] = row.rp_domain
      }

      var rpids_where = ' rp_id in (' + results.map(d => d.rp_id).join(',') + ') '
      var search_where = search && search.length >0 ? ' username like "%'+search+'%" ':' 1=1 '
      var last_created_where = last_created && last_created.length >0 ? ' a.created < "'+last_created+'" ':' 1=1 '
      var failed_where = fail_only?' error<>"" ':' 1=1 '
      results = await new Promise((resolve, reject) => {
        connection.query('SELECT action_id, rp_id, username, displayname, a.created, error, action_type from user_actions a, registered_users r '+
              'where '+ rpids_where + ' and ' + search_where + ' and ' + last_created_where + ' and ' + failed_where +
              ' and a.user_id=r.user_id and deleted is null and a.created between ? and ? order by a.created desc limit ' + limit, 
            [start, end],
            (error, results) => {
              if (error) reject(error)
              resolve(results)
            })
      })

      //list user's devices
      var last_created = null;
      for (const row of results) {
        row.domain = rp_domain_rp_id[row.rp_id]
        row.err = row.error
        last_created = row.created
      }
      rtn.actions = results      
      rtn.last_created = last_created
    }catch (err) {      
      logger.error('DB err:'+err)
    } finally {
      connection.release()
    }
  }else{
    logger.error('Unsupport listUsers for process.env.STORAGE_TYPE:' + process.env.STORAGE_TYPE);
  }
  return rtn;
}

async function delUser(domains, user_id){
  var rtn = {};
  if('mysql'==process.env.STORAGE_TYPE){
    const connection = await new Promise((resolve, reject) => {
      mysql_pool.getConnection((error, connection) => {
        if (error) reject(error)
        resolve(connection)
      })
    })

    try {
      var domains_where = ' r.rp_domain in ("' + domains.map(d => d).join('","') + '") and '

      var results = await new Promise((resolve, reject) => {
        connection.query('SELECT rp_id, rp_domain from registered_rps r '+
              'where '+ domains_where +' deleted is null ', 
            [],
            (error, results) => {
              if (error) reject(error)
              resolve(results)
            })
      })
      
      var rpids_where = ' rp_id in (' + results.map(d => d.rp_id).join(',') + ') '
      results = await new Promise((resolve, reject) => {
        connection.query('SELECT count(*) cnt from registered_users '+
              'where '+ rpids_where + ' and user_id=? and registered=true and deleted is null ', 
            [user_id],
            (error, results) => {
              if (error) reject(error)
              resolve(results)
            })
      })

      if(0<results.length && 0<results[0].cnt){
        results = await new Promise((resolve, reject) => {
          connection.query('update attestations set deleted=now() where user_id=? and deleted is null',
              [user_id],
              (error, results) => {
                if (error) reject(error)
                resolve(results)
              })
        })
        results = await new Promise((resolve, reject) => {
          connection.query('update registered_users set deleted=now() where user_id=? and deleted is null',
              [user_id],
              (error, results) => {
                if (error) reject(error)
                resolve(results)
              })
        })
        rtn.status = 'ok';
      }else{
        rtn.status = 'fail';
      }    
    }catch (err) {      
      logger.error('DB err:'+err)
      rtn.status = 'fail';
    } finally {
      connection.release()
    }
  }else{
    logger.error('Unsupport delUser for process.env.STORAGE_TYPE:' + process.env.STORAGE_TYPE);
  }
  return rtn;
}

//Delete user's device
async function delDevice(domains, attest_id){
  var rtn = {};
  if('mysql'==process.env.STORAGE_TYPE){
    const connection = await new Promise((resolve, reject) => {
      mysql_pool.getConnection((error, connection) => {
        if (error) reject(error)
        resolve(connection)
      })
    })

    try {
      var domains_where = ' r.rp_domain in ("' + domains.map(d => d).join('","') + '") and '

      var results = await new Promise((resolve, reject) => {
        connection.query('SELECT rp_id, rp_domain from registered_rps r '+
              'where '+ domains_where +' deleted is null ', 
            [],
            (error, results) => {
              if (error) reject(error)
              resolve(results)
            })
      })

      var rpids_where = ' u.rp_id in (' + results.map(d => d.rp_id).join(',') + ') '
      results = await new Promise((resolve, reject) => {
        connection.query('SELECT count(*) cnt from registered_users u, attestations a '+
              'where '+ rpids_where + ' and a.attest_id=? and u.registered=true and a.deleted is null and u.deleted is null '+
              'and u.user_id=a.user_id ', 
            [attest_id],
            (error, results) => {
              if (error) reject(error)
              resolve(results)
            })
      })

      if(0<results.length && 0<results[0].cnt){
        results = await new Promise((resolve, reject) => {
          connection.query('update attestations set deleted=now() where attest_id=?',
              [attest_id],
              (error, results) => {
                if (error) reject(error)
                resolve(results)
              })
        })
        rtn.status = 'ok';
      }else{
        rtn.status = 'fail';
      }    
    }catch (err) {      
      logger.error('DB err:'+err)
      rtn.status = 'fail';
    } finally {
      connection.release()
    }
  }else{
    logger.error('Unsupport delDevice for process.env.STORAGE_TYPE:' + process.env.STORAGE_TYPE);
  }
  return rtn;
}

async function generateRegSession(username){
  var session_id = null;
  if('mysql'==process.env.STORAGE_TYPE){
    const connection = await new Promise((resolve, reject) => {
      mysql_pool.getConnection((error, connection) => {
        if (error) reject(error)
        resolve(connection)
      })
    })

    try {   
           
      session_id = uuidv4()

      const results = await new Promise((resolve, reject) => {
      connection.query('INSERT into registration_sessions( session_id, username ) values(?,?) ', 
          [session_id, username],
          (error, results) => {
            if (error) reject(error)
            resolve(results)
          })
      })
      
    }catch (err) {
      logger.error('DB err: '+err)
      session_id = null
    } finally {
      connection.release()
    }
  }else{
    logger.error('Unsupport generateRegSession for process.env.STORAGE_TYPE:' + process.env.STORAGE_TYPE);
  }
  return session_id
}

async function getRegSessionUsername(session_id) {
  var rtn = null
  if ('mysql' == process.env.STORAGE_TYPE) {
    const connection = await new Promise((resolve, reject) => {
      mysql_pool.getConnection((error, connection) => {
        if (error) reject(error)
        resolve(connection)
      })
    })

    try { 
      var results = await new Promise((resolve, reject) => {
        connection.query('select session_id, username from registration_sessions where session_id = ? ',
          [session_id],
          (error, results) => {
            if (error) reject(error)
            resolve(results)
          })
      })
      if (0 < results.length) {
        rtn = results[0].username

        // A session only can be used one time.
        results = await new Promise((resolve, reject) => {
        connection.query('delete from registration_sessions where session_id = ? ',
          [results[0].session_id],
          (error, results) => {
            if (error) reject(error)
            resolve(results)
          })
        })
      }
    } catch (err) {
      logger.error('DB err: ' + err)
      session_id = null
    } finally {
      connection.release()
    }
  } else {
    logger.error('Unsupport generateRegSession for process.env.STORAGE_TYPE:' + process.env.STORAGE_TYPE);
  }
  return rtn
}

async function clearTimeoutSessions(){
  var rtn = false;
  if('mem'==process.env.STORAGE_TYPE){
    logger.warn('mem storage does not support clearTimeoutSessions')
  }else if('mysql'==process.env.STORAGE_TYPE){
    const connection = await new Promise((resolve, reject) => {
      mysql_pool.getConnection((error, connection) => {
        if (error) reject(error)
        resolve(connection)
      })
    })

    try {
      const results = await new Promise((resolve, reject) => {
        connection.query('SELECT rp_domain, rp_id from registered_rps where deleted is null',
            (error, results) => {
              if (error) reject(error)
              resolve(results)
            })
      })
      for (const row of results) {
        await new Promise((resolve, reject) => {
          const rpid = row.rp_id;
          const htm = userSessionHardTimeout.get(row.rp_domain)
          const atm = userSessionActiveTimeout.get(row.rp_domain)
          connection.query('delete from user_sessions u where exists (select * from registered_users r where r.rp_id = ? and r.user_id = u.user_id) '+
                ' and (TIMESTAMPDIFF(SECOND, u.created, NOW()) > ? or TIMESTAMPDIFF(SECOND, u.actived, NOW()) > ?)', 
              [rpid, htm, atm],
              (error, results) => {
                if (error) reject(error)
                resolve(results)
              })

          const regtm = regSessionTimeout.get(row.rp_domain)
          connection.query('delete from registration_sessions where TIMESTAMPDIFF(SECOND, created, NOW()) > ? ', 
              [regtm],
              (error, results) => {
                if (error) reject(error)
                resolve(results)
              })
        })
      }
      
    }catch (err) {      
      logger.error('DB err:'+err)
    } finally {
      connection.release()
    }
  }else{
    logger.error('Unknown process.env.STORAGE_TYPE:' + process.env.STORAGE_TYPE);
  }
}

async function setRps(registeredRps){
  if('mysql'==process.env.STORAGE_TYPE){
    const connection = await new Promise((resolve, reject) => {
      mysql_pool.getConnection((error, connection) => {
        if (error) reject(error)
        resolve(connection)
      })
    })

    try {
      const results = await new Promise((resolve, reject) => {
        connection.query('SELECT rp_domain from registered_rps where deleted is null',
            (error, results) => {
              if (error) reject(error)
              resolve(results)
            })
      })
      var newRps = registeredRps
      var delRps = []
      results.forEach(element => {
        if(newRps.includes(element.rp_domain)){
          newRps = newRps.filter(item => !item.match(element.rp_domain));
        }else{
          delRps.push(element.rp_domain)          
        }
      });
    
      for (const element of newRps) {
        const results = await new Promise((resolve, reject) => {
          connection.query('INSERT into registered_rps( rp_domain ) values(?)', 
              [element],
              (error, results) => {
                if (error) reject(error)
                resolve(results)
              });
        });
      }
      for (const element of delRps) {
        const results = await new Promise((resolve, reject) => {
          connection.query('update registered_rps set deleted=NOW() where rp_domain =?', 
              [element],
              (error, results) => {
                if (error) reject(error)
                resolve(results)
              })
        })
      }
    }catch (err) {      
      logger.error('DB err:'+err)
    } finally {
      connection.release()
    }
  }
}

async function getUserData(rpId, username){
  if('mem'==process.env.STORAGE_TYPE){
    return database.get(rpId).get(username)
  }else if('mysql'==process.env.STORAGE_TYPE){
    const connection = await new Promise((resolve, reject) => {
      mysql_pool.getConnection((error, connection) => {
        if (error) reject(error)
        resolve(connection)
      })
    })

    try {
      const results = await new Promise((resolve, reject) => {
        connection.query('SELECT user_id, username, displayname, registered '+
            ' from registered_rps p, registered_users u ' +
            ' where p.deleted is null and u.deleted is null ' +
            ' and p.rp_id=u.rp_id and p.rp_domain=? and u.username=?', [rpId, username],
            (error, results) => {
              if (error) reject(error)
              resolve(results)
            })
      })
      if(0<results.length){
        return {
          id:results[0].user_id,
          displayname:results[0].displayname,
          registered:results[0].registered 
        }        
      }else return null
    }catch (err) {      
      logger.error('DB err:'+err)
    } finally {
      connection.release()
    }
  }else{
    logger.error('Unknown process.env.STORAGE_TYPE:' + process.env.STORAGE_TYPE);
  }
}

async function getAttestationData(rpId, username){
  if('mem'==process.env.STORAGE_TYPE){
    return database.get(rpId).get(username).attestation
  }else if('mysql'==process.env.STORAGE_TYPE){
    const connection = await new Promise((resolve, reject) => {
      mysql_pool.getConnection((error, connection) => {
        if (error) reject(error)
        resolve(connection)
      })
    })

    try {
      const results = await new Promise((resolve, reject) => {
        connection.query('SELECT public_key, counter, fmt, aaguid, credid_base64, t.unique_device_id '+
            ' from registered_rps p, registered_users u, attestations t ' +
            ' where p.deleted is null and u.deleted is null and t.deleted is null ' +
            ' and p.rp_id=u.rp_id and t.user_id=u.user_id '+
            ' and p.rp_domain=? and u.username=?', [rpId, username],
            (error, results) => {
              if (error) reject(error)
              resolve(results)
            })
      })
      var rtn=[]
      if(0<results.length){
        results.forEach(element => {          
          rtn.push({
            publickey:element.public_key,
            counter:element.counter,
            fmt:element.fmt,
            aaguid:element.aaguid,
            credId:base64url.toBuffer(element.credid_base64),
            unique_device_id: element.unique_device_id
          })
        });
      }
      return rtn
    }catch (err) {      
      logger.error('DB err:'+err)
    } finally {
      connection.release()
    }
  }else{
    logger.error('Unknown process.env.STORAGE_TYPE:' + process.env.STORAGE_TYPE);
  }
}

async function discoverUserName(credId){
  if('mem'==process.env.STORAGE_TYPE){
    return mapCredidUsername[credId]
  }else if('mysql'==process.env.STORAGE_TYPE){
    const connection = await new Promise((resolve, reject) => {
      mysql_pool.getConnection((error, connection) => {
        if (error) reject(error)
        resolve(connection)
      })
    })

    try {
      const results = await new Promise((resolve, reject) => {
        connection.query('SELECT u.username from registered_users u, attestations t '+
              ' where t.deleted is null and u.deleted is null and t.credid_base64=? and u.user_id=t.user_id ', 
            [base64url.encode(credId)],
            (error, results) => {
              if (error) reject(error)
              resolve(results)
            })
      })
      if(0<results.length)return results[0].username
      else return null
    }catch (err) {      
      logger.error('DB err:'+err)
    } finally {
      connection.release()
    }
  }else{
    logger.error('Unknown process.env.STORAGE_TYPE:' + process.env.STORAGE_TYPE);
  }
}

async function listUserDevices(rpId, session_id){
  var rtn=[]
  activeUserSession(rpId, session_id);
  if('mem'==process.env.STORAGE_TYPE){
    const atts = database.get(rpId).get(user_sessions.get(session_id)).attestation
    var index = 0;
    if(atts){
      for(let att of atts) {
        const meta_entry = await mds3_client.findByAAGUID(att.aaguid)      
        rtn.push({
          device_id: index,
          userAgent: att.userAgent?att.userAgent:"",
          desc: meta_entry && meta_entry.metadataStatement && meta_entry.metadataStatement.description ? 
              meta_entry.metadataStatement.description:"",
          registered_time: new Date()
        })
        index++;
      }
    }    
  }else if('mysql'==process.env.STORAGE_TYPE){
    const connection = await new Promise((resolve, reject) => {
      mysql_pool.getConnection((error, connection) => {
        if (error) reject(error)
        resolve(connection)
      })
    })

    try {
      const results = await new Promise((resolve, reject) => {
        connection.query('SELECT t.attest_id, t.aaguid, t.user_agent, t.created from attestations t, user_sessions s ' +
            ' where t.deleted is null and s.user_id=t.user_id '+
            ' and s.session_id=?', [session_id],
            (error, results) => {
              if (error) reject(error)
              resolve(results)
            })
      })
      if(0<results.length){
        for(let elm of results) {  
          const meta_entry = await mds3_client.findByAAGUID(elm.aaguid)
          rtn.push({
            device_id: elm.attest_id,
            userAgent: elm.user_agent?elm.user_agent:"",
            desc: meta_entry && meta_entry.metadataStatement && meta_entry.metadataStatement.description ? 
                meta_entry.metadataStatement.description:"",
            registered_time: elm.created
          })
        }
      }
    }catch (err) {      
      logger.error('DB err:'+err)
    } finally {
      connection.release()
    }
  }else{
    logger.error('Unknown process.env.STORAGE_TYPE:' + process.env.STORAGE_TYPE);
  }

  return rtn
}

async function delUserDevices(rpId, session_id, device_id){
  var rtn=-415
  activeUserSession(rpId, session_id);
  if('mem'==process.env.STORAGE_TYPE){
    const att = database.get(rpId).get(user_sessions.get(session_id)).attestation
    if(att && device_id < att.length){
      att.splice(device_id, 1);
      //database.get(rpId).get(user_sessions.get(session_id)).attestation = att;
      rtn = att.length;
    }
  }else if('mysql'==process.env.STORAGE_TYPE){
    const connection = await new Promise((resolve, reject) => {
      mysql_pool.getConnection((error, connection) => {
        if (error) reject(error)
        resolve(connection)
      })
    })

    try {      
        const results = await new Promise((resolve, reject) => {
          connection.query('Update attestations set deleted=NOW() ' +
              ' where attest_id=? ', [device_id],
              (error, results) => {
                if (error) reject(error)
                resolve(results)
              })
        });

        const cnt_result = await new Promise((resolve, reject) => {
          connection.query('SELECT count(*) cnt from attestations a, user_sessions s '+
                'where a.deleted is null and s.user_id=a.user_id and s.session_id=? ', [session_id],
              (error, results) => {
                if (error) reject(error)
                resolve(results)
              })
        })
        rtn=cnt_result[0].cnt
    }catch (err) {      
      logger.error('DB err:'+err)
    } finally {
      connection.release()
    }
  }else{
    logger.error('Unknown process.env.STORAGE_TYPE:' + process.env.STORAGE_TYPE);
  }

  return rtn
}

async function putUserData(rpId, username, userid, displayname, registered){
  if('mem'==process.env.STORAGE_TYPE){
    database.get(rpId).set(username,{
      'displayname': displayname,
      'registered': registered,
      'id': userid,//Record non base64 user id
      'attestation': []
    });

    //console.log("putUserData:" + username)
  }else if('mysql'==process.env.STORAGE_TYPE){
    const connection = await new Promise((resolve, reject) => {
      mysql_pool.getConnection((error, connection) => {
        if (error) reject(error)
        resolve(connection)
      })
    })

    try {
      const ipid_result = await new Promise((resolve, reject) => {
        connection.query('SELECT rp_id from registered_rps where deleted is null and rp_domain=? ', [rpId],
            (error, results) => {
              if (error) reject(error)
              resolve(results)
            })
      })
      if(0<ipid_result.length){
        const results = await new Promise((resolve, reject) => {
          connection.query('INSERT into registered_users( rp_id, user_id, username, displayname, registered ) values(?,?,?,?,?) ', 
              [ipid_result[0].rp_id, userid, username, displayname, registered],
              (error, results) => {
                if (error) reject(error)
                resolve(results)
              })
        })
      }      
    }catch (err) {
      logger.error('DB err:'+err)
    } finally {
      connection.release()
    }
  }else{
    logger.error('Unknown process.env.STORAGE_TYPE:' + process.env.STORAGE_TYPE);
  }
}

async function generateUserSession(rpId, username){
  var session_id = uuidv4();

  if('mem'==process.env.STORAGE_TYPE){
    user_sessions.set(session_id, username)
  }else if('mysql'==process.env.STORAGE_TYPE){
    const connection = await new Promise((resolve, reject) => {
      mysql_pool.getConnection((error, connection) => {
        if (error) reject(error)
        resolve(connection)
      })
    })

    try {
      const result_userid = await new Promise((resolve, reject) => {
        connection.query('SELECT user_id from registered_rps p, registered_users u ' +
            ' where p.deleted is null and u.deleted is null ' +
            ' and p.rp_id=u.rp_id and p.rp_domain=? and u.username=?', [rpId, username],
            (error, results) => {
              if (error) reject(error)
              resolve(results)
            })
      })
      if(0<result_userid.length){
        const results = await new Promise((resolve, reject) => {
          connection.query('INSERT into user_sessions( session_id, user_id ) values(?,?) ', 
              [session_id, result_userid[0].user_id],
              (error, results) => {
                if (error) reject(error)
                resolve(results)
              })
          })    
      }
    }catch (err) {
      logger.error('DB err:'+err)
      session_id = null
    } finally {
      connection.release()
    }
  }else{
    logger.error('Unknown process.env.STORAGE_TYPE:' + process.env.STORAGE_TYPE);
  }
  return session_id
}

async function recordUserAction(rpId, username, action_type, action_session, error = ''){
  var action_id = uuidv4();

  if('mysql'==process.env.STORAGE_TYPE){
    const connection = await new Promise((resolve, reject) => {
      mysql_pool.getConnection((error, connection) => {
        if (error) reject(error)
        resolve(connection)
      })
    })

    try {
      const result_userid = await new Promise((resolve, reject) => {
        connection.query('SELECT user_id from registered_rps p, registered_users u ' +
            ' where p.deleted is null and u.deleted is null ' +
            ' and p.rp_id=u.rp_id and p.rp_domain=? and u.username=?', [rpId, username],
            (error, results) => {
              if (error) reject(error)
              resolve(results)
            })
      })
      if(0<result_userid.length){
        const results = await new Promise((resolve, reject) => {
          connection.query('INSERT into user_actions( action_id, user_id, action_type, action_session, error ) values(?,?,?,?,?) ', 
              [action_id, result_userid[0].user_id, action_type, action_session, error],
              (error, results) => {
                if (error) reject(error)
                resolve(results)
              })
          });
      }
    }catch (err) {
      logger.error('DB err:'+err)
      action_id = null
    } finally {
      connection.release()
    }
  }else{
    logger.error('Unsupport process.env.STORAGE_TYPE for recordUserAction:' + process.env.STORAGE_TYPE);
  }
  return action_id
}

async function activeUserSession(rpId, session_id){
  var rtn = false;
  if('mem'==process.env.STORAGE_TYPE){
    logger.warn('mem storage does not support activeUserSession')
  }else if('mysql'==process.env.STORAGE_TYPE){
    const connection = await new Promise((resolve, reject) => {
      mysql_pool.getConnection((error, connection) => {
        if (error) reject(error)
        resolve(connection)
      })
    })

    try {
      const results = await new Promise((resolve, reject) => {
        connection.query('update user_sessions set actived = now() where session_id = ? and TIMESTAMPDIFF(SECOND, created, NOW()) < ? and TIMESTAMPDIFF(SECOND, actived, NOW()) < ?', 
        [session_id, userSessionHardTimeout.get(rpId), userSessionActiveTimeout.get(rpId)],
        (error, results) => {
          if (error) reject(error)
          resolve(results)
        })
      })
    }catch (err) {      
      logger.error('DB err:'+err)
    } finally {
      connection.release()
    }
  }else{
    logger.error('Unknown process.env.STORAGE_TYPE:' + process.env.STORAGE_TYPE);
  }
}

async function pushAttestation(rpId, username, publickey, counter, fmt, credId, aaguid, unique_device_id, user_agent){
  if('mem'==process.env.STORAGE_TYPE){
    //console.log("try pushAttestation:" + username)
    database.get(rpId).get(username).attestation.push({
      publickey: publickey,
      counter: counter,
      fmt: counter,
      credId: credId,
      aaguid: aaguid,
      userAgent: user_agent,
      unique_device_id: unique_device_id
    })

    //console.log("pushAttestation:" + username)
  }else if('mysql'==process.env.STORAGE_TYPE){
    const connection = await new Promise((resolve, reject) => {
      mysql_pool.getConnection((error, connection) => {
        if (error) reject(error)
        resolve(connection)
      })
    })

    try {
      const result_userid = await new Promise((resolve, reject) => {
        connection.query('SELECT user_id from registered_rps p, registered_users u ' +
            ' where p.deleted is null and u.deleted is null ' +
            ' and p.rp_id=u.rp_id and p.rp_domain=? and u.username=?', [rpId, username],
            (error, results) => {
              if (error) reject(error)
              resolve(results)
            })
      })
      if(0<result_userid.length){
        const results = await new Promise((resolve, reject) => {
          connection.query(
            'INSERT into attestations( user_id, public_key, counter, fmt, credid_base64, aaguid, unique_device_id, user_agent ) values(?,?,?,?,?,?,?,?) ', 
              [result_userid[0].user_id, publickey, counter, fmt, base64url.encode(credId), aaguid, unique_device_id?unique_device_id:'', user_agent],
              (error, results) => {
                if (error) reject(error)
                resolve(results)
              })
        })
      }
    }catch (err) {  
      logger.error('DB err:'+err)
    } finally {
      connection.release()
    }
  }else{
    logger.error('Unknown process.env.STORAGE_TYPE:' + process.env.STORAGE_TYPE);
  }
}

async function setRegistered(rpId, username, registered){
  if('mem'==process.env.STORAGE_TYPE){
    database.get(rpId).get(username).registered = registered
  }else if('mysql'==process.env.STORAGE_TYPE){
    const connection = await new Promise((resolve, reject) => {
      mysql_pool.getConnection((error, connection) => {
        if (error) reject(error)
        resolve(connection)
      })
    })

    try {
      const results = await new Promise((resolve, reject) => {
        connection.query('update registered_users u set registered=? where u.deleted is null and '+
            ' username=? and rp_id=(select rp_id from registered_rps where deleted is null and rp_domain=?) ', 
            [registered, username, rpId],
            (error, results) => {
              if (error) reject(error)
              resolve(results)
            })
      })
    }catch (err) {      
      logger.error('DB err:'+err)
    } finally {
      connection.release()
    }
  }else{
    logger.error('Unknown process.env.STORAGE_TYPE:' + process.env.STORAGE_TYPE);
  }  
}

async function bindedDeviceKey(rpId, username, publickey, unique_device_id){
  if('mem'==process.env.STORAGE_TYPE){
    let db_publickey = database.get(rpId).get(username).attestation.publickey
    let db_unique_device_id = database.get(rpId).get(username).unique_device_id
    return database.get(rpId).get(username).registered &&  db_publickey === publickey && 
        db_unique_device_id === unique_device_id
  }else if('mysql'==process.env.STORAGE_TYPE){
    const connection = await new Promise((resolve, reject) => {
      mysql_pool.getConnection((error, connection) => {
        if (error) reject(error)
        resolve(connection)
      })
    })

    try {
      const result_device = await new Promise((resolve, reject) => {
        connection.query('SELECT attest_id from registered_rps p, registered_users u, attestations a ' +
            ' where p.deleted is null and u.deleted is null and a.deleted is null and registered = true ' +
            ' and p.rp_id=u.rp_id and a.user_id=u.user_id and p.rp_domain=? and u.username=? and a.public_key=? and a.unique_device_id=? ',
            [rpId, username, publickey, unique_device_id],
            (error, results) => {
              if (error) reject(error)
              resolve(results)
            })
      })
      return 0<result_device.length
    }catch (err) {      
      logger.error('DB err:'+err)
    } finally {
      connection.release()
    }
  }else{
    logger.error('Unknown process.env.STORAGE_TYPE:' + process.env.STORAGE_TYPE);
  }  
}