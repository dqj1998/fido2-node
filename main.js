
const https = require("https");
const base64url = require('base64url');
const crypto    = require('crypto');
const fs        = require('fs');
const log4js    = require('log4js');

require('dotenv').config();

const { v4: uuidv4 } = require('uuid');
//const { Fido2Lib } = require("fido2-lib");

const { env } = require("process");

log4js.configure('log4js-conf.json');
const logger = log4js.getLogger();
//logger.level = process.env.LOG4JS_LEVEL;

const port = process.env.PORT || 443;

const mysql = require('mysql2');
const mysql_pool = mysql.createPool({
  connectionLimit : process.env.MYSQL_POOL_LIMIT || 10,
  host: process.env.MYSQL_HOST || 'localhost',
  database: process.env.MYSQL_DATABASE || 'fido2_node_db',
  user: process.env.MYSQL_USER || 'root',
  password: process.env.MYSQL_PASSWD || '',
});

const options = {
  key: fs.readFileSync(process.env.SSLKEY),
  cert: fs.readFileSync(process.env.SSLCRT)
};
const server = https.createServer(options)

const DEFAULT_FIDO_RPID = process.env.DEFAULT_FIDO_RPID
const FIDO_ORIGIN = process.env.FIDO_ORIGIN

const DOMAIN_JSON_FN = 'domain.json';
var domains_conf
var registeredRps
var enterpriseRps
var enterpriseAaguids;

let database = new Map();//use json as DB, all data will lost after restart program.

loadDomains();

let mapCredidUsername = {};//Link cred ids with usernames
let sessions = {};

server.on('request', AppController);

server.listen(port);
//console.log(`Started server: ${port}`);
logger.info(`Started server: ${port}`);

function loadDomains(){
  domains_conf = JSON.parse(fs.readFileSync(DOMAIN_JSON_FN, 'utf8'));
  
  registeredRps = [];
  enterpriseRps = [];
  enterpriseAaguids = new Map();

  domains_conf.domains.forEach(element => {  
    registeredRps.push(element.domain)
    if(element.enterprise){
      enterpriseRps.push(element.domain)

      if(element.enterprise_aaguids){
        enterpriseAaguids.set(element.domain, element.enterprise_aaguids)
      }
    }
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
    
        //Client-side discoverable Credential does not pass username

        let rpId=checkRpId(body, response)
        if(null==rpId)return

        let user = await getUserData(rpId, username)
        if(username && username.length > 0 && (!user || !user.registered)) {
          response.end(JSON.stringify({
            'status': 'failed',
            'message': `Username ${username} does not exist`
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
          //console.log(authnOptions);
          logger.debug(authnOptions);
        }
            
        sessions[challengeBase64] = {
          'challenge': authnOptions.challenge,
          'username': username?username:"",
          'fido2lib': fido2Lib,
        };
    
        authnOptions.status = 'ok';
    
        response.end(JSON.stringify(authnOptions));
      }else if(url.pathname == '/assertion/result'){
        const body = await loadJsonBody(request)

        const clientData = JSON.parse(stringfy(body.response.clientDataJSON))
        
        body.response.authenticatorData = new Uint8Array(base64url.toBuffer(body.response.authenticatorData)).buffer; //bufferKeepBase64(body.response.authenticatorData)
        body.response.signature = new Uint8Array(base64url.toBuffer(body.response.signature)).buffer; //bufferKeepBase64((body.response.signature))
        body.response.userHandle = base64url.toBuffer(body.response.userHandle); //new TextDecoder().decode(new Uint8Array(base64url.toBuffer(body.response.userHandle)).buffer)   
        body.response.userHandle = stringfy(body.response.userHandle)//new TextDecoder().decode(body.response.userHandle)
        body.response.clientDataJSON = new Uint8Array(base64url.toBuffer(body.response.clientDataJSON)).buffer; //bufferKeepBase64(body.response.clientDataJSON)
    
        let attestation = null;

        //let debugId=new Uint8Array(base64url.toBuffer(body.id)).buffer//for debug
        var reqId
        if( body.rawId ){
          reqId = new Uint8Array(body.rawId);
        }
        if( !reqId || reqId.length == 0){
          reqId = new Uint8Array(base64url.toBuffer(body.id))
        }          
        body.rawId = reqId.buffer;

        var realUsername;
        var attestations;
        if(sessions[clientData.challenge].username && sessions[clientData.challenge].username.length > 0){          
          realUsername = sessions[clientData.challenge].username
        }else if(mapCredidUsername[reqId]){//Client-side discoverable Credential process
          realUsername = mapCredidUsername[reqId];
        }

        if(null==sessions[clientData.challenge].fido2lib)return

        if(realUsername){
          attestations = await getAttestationData(sessions[clientData.challenge].fido2lib.config.rpId, realUsername)
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
            'message': 'key is not found.'
          }
          response.end(JSON.stringify(rtn));
          return
        }

        const cur_session = sessions[clientData.challenge]
        delete sessions[clientData.challenge]

        let user = await getUserData(cur_session.fido2lib.config.rpId, realUsername)
        let assertionExpectations = {
          challenge: cur_session.challenge,
          origin: FIDO_ORIGIN,
          rpId: cur_session.fido2lib.config.rpId,
          factor: "either",
          publicKey: attestation.publickey,
          prevCounter: attestation.counter,
          userHandle: user.id
        };    
        
        let authnResult = await cur_session.fido2lib.assertionResult(body, assertionExpectations);
        //console.log(authnResult);
        logger.debug(authnResult)
    
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

        let rpId=checkRpId(body, response)
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
          registrationOptions.excludeCredentials = excludeCredentials
        }        

        registrationOptions.user.id = base64url.encode(userid);
        registrationOptions.user.name = username;
        registrationOptions.user.displayName = body.displayName?body.displayName:username;

        if(fido2Lib.config.attestation){
          registrationOptions.attestation = fido2Lib.config.attestation
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

        response.end(JSON.stringify(registrationOptions));

      }else if( url.pathname == '/attestation/result'){
        const body = await loadJsonBody(request)
        
        const clientData = JSON.parse(stringfy(body.response.clientDataJSON))

        /*const tpAtt = typeof body.response.attestationObject //for debug
        const attobj=new Buffer.from(body.response.attestationObject)
        var ab = new ArrayBuffer(attobj.length);
        var view = new Uint8Array(ab);
        for (var i = 0; i < attobj.length; ++i) {
            view[i] = attobj[i];
        }*/
        body.rawId = new Uint8Array(base64url.toBuffer(body.rawId)).buffer; //bufferKeepBase64(body.rawId); 
        body.response.attestationObject = new Uint8Array(base64url.toBuffer(body.response.attestationObject)).buffer//bufferKeepBase64(body.response.attestationObject)        
        body.response.clientDataJSON = new Uint8Array(base64url.toBuffer(body.response.clientDataJSON)).buffer; //bufferKeepBase64(body.response.clientDataJSON)
        
        const cur_session = sessions[clientData.challenge]
        delete sessions[clientData.challenge]

        if(null==cur_session.fido2lib)return

        let attestationExpectations = {
            challenge: cur_session.challenge,
            origin: FIDO_ORIGIN,
            rpId: cur_session.fido2lib.config.rpId,
            factor: "either"
        };
        
        let regResult = await cur_session.fido2lib.attestationResult(body, attestationExpectations);
        logger.debug(regResult);
        

        const credId = regResult.authnrData.get('credId')
        const aaguid = buf2hex(regResult.authnrData.get('aaguid'))

        let rtn={};

        const aaguidtxt = String.fromCharCode.apply("", new Uint8Array(regResult.authnrData.get('aaguid')))
        if(cur_session.fido2lib.config.attestation == "enterprise"){
          const guids = enterpriseAaguids.get(cur_session.fido2lib.config.rpId)
          if(!guids || !guids.includes(aaguidtxt) ){
            rtn.status ='failed',
            rtn.message = 'Unregistered enterprise authenticator aaguid!'
          }
        }

        if(!rtn.status){
          const counter = regResult.authnrData.get('counter');
          await pushAttestation(cur_session.fido2lib.config.rpId, cur_session.username, 
            regResult.authnrData.get('credentialPublicKeyPem'), counter, regResult.authnrData.get('fmt'),
            new Uint8Array(credId), aaguid);
          
          mapCredidUsername[new Uint8Array(credId)]=cur_session.username;
          
          if(regResult.audit.complete) {
            await setRegistered(cur_session.fido2lib.config.rpId, cur_session.username, true)         
      
            rtn.status = 'ok',
            rtn.counter = counter
            rtn.credId = Array.from(new Uint8Array(regResult.authnrData.get('credId')))
          } else {
            rtn.status ='failed',
            rtn.message = 'Can not authenticate signature!'
          }  
        }
        
        response.end(JSON.stringify(rtn));
      }
      // ====== Management methods ======
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
                for (let i = 0; i < domains_conf.domains.length; ++i) {
                  if( element.domain == domains_conf.domains[i].domain){
                    domains_conf.domains[i]=element;
                  }
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
              rtn = {status:'error'}
              logger.warn('Backup file does not exist:' + (domains_conf.backupFileName?domains_conf.backupFileName:'null'));
            }
            
            response.end(JSON.stringify(rtn));
          }          
        }else{
          logger.warn('Somebody tried to access mng path:('+request.socket.remoteAddress+') with token='+
              (body.MNG_TOKEN?body.MNG_TOKEN:'null'));
          response.end("");
        }        
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
    //console.log('clientDataJSON:'); console.log(cltdatatxt)
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
    timeout: 300 * 1000 //ms
  }

  if(enterpriseRps.includes(rp)){
    opts.attestation = "enterprise"
  }

  if(null!=reqBody){
    if(reqBody.authenticatorSelection){
      opts.authenticatorUserVerification=reqBody.authenticatorSelection.userVerification
    }
  }

  let f2lib = require('./fido2-node-lib/main'); //new Fido2Lib(opts);

  return new f2lib(opts)
}

function checkRpId(reqBody, response){
  if(reqBody.rp && reqBody.rp.id){
    if(registeredRps.includes(reqBody.rp.id)){
      return reqBody.rp.id
    }else{
      response.end(
        JSON.stringify({
          'status': 'failed',
          'message': `No exist rp.id: ${reqBody.rp.id}`
        })
      );
        //JSON.stringify({"status": "failed", "message":"No exist rp.id:"+reqBody.rp.id}));
      return null
    }
  } else return DEFAULT_FIDO_RPID
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
      logger.error('DB err'+err)
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
      logger.error('DB err'+err)
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
        connection.query('SELECT public_key, counter, fmt, aaguid, credid_base64 '+
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
            credId:base64url.toBuffer(element.credid_base64)
          })
        });
      }
      return rtn
    }catch (err) {      
      logger.error('DB err'+err)
    } finally {
      connection.release()
    }
  }else{
    logger.error('Unknown process.env.STORAGE_TYPE:' + process.env.STORAGE_TYPE);
  }
}

async function putUserData(rpId, username, userid, displayname, registered){
  if('mem'==process.env.STORAGE_TYPE){
    database.get(rpId).set(username,{
      'displayname': displayname,
      'registered': registered,
      'id': userid,//Record non base64 user id
      'attestation': []
    });
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
      logger.error('DB err'+err)
    } finally {
      connection.release()
    }
  }else{
    logger.error('Unknown process.env.STORAGE_TYPE:' + process.env.STORAGE_TYPE);
  }
}

async function pushAttestation(rpId, username, publickey, counter, fmt, credId, aaguid){
  if('mem'==process.env.STORAGE_TYPE){
    database.get(rpId).get(username).attestation.push({
      publickey: publickey,
      counter: counter,
      fmt: counter,
      credId: credId,
      aaguid: aaguid
    })
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
          connection.query('INSERT into attestations( user_id, public_key, counter, fmt, credid_base64, aaguid ) values(?,?,?,?,?,?) ', 
              [result_userid[0].user_id, publickey, counter, fmt, base64url.encode(credId), aaguid],
              (error, results) => {
                if (error) reject(error)
                resolve(results)
              })
        })
      }
    }catch (err) {  
      logger.error('DB err'+err)
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
      logger.error('DB err'+err)
    } finally {
      connection.release()
    }
  }else{
    logger.error('Unknown process.env.STORAGE_TYPE:' + process.env.STORAGE_TYPE);
  }  
}
