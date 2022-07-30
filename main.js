const http = require("http");

const port = 3000;
const server = http.createServer();

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
   
  }
  
}
