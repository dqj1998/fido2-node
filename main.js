const http = require("http");
const port = 3000;

const server = http.createServer((request, response) => {
    const url = new URL(request.url, `http://${request.headers.host}`)
    
    response.writeHead(200, {
      "Content-Type": "text/html"
    });

    const responseMessage = "<h1>Hello World, dqj1998</h1>";
    response.end(responseMessage);
    console.log(`Responsed : ${responseMessage}`);
});

server.listen(port);
console.log(`Started server: ${port}`);