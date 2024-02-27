import net from "net"
import dns from "dns"

const server = net.createServer((socket) => {
    socket.on('error', (err) => {
        if(err.message.includes("ECONNRESET")){
            return;
        }

        throw err;
    });

    socket.once("data", (data) => {
        let VER = data.readUint8(0); // socks version
        let NAUTH = data.readInt8(1); // number of supported auth metods
        let AUTHs = []

        for(let i = 0; i < NAUTH; i++){
            let AUTH = data.readInt8(i + 2); // Supported auth method
            AUTHs.push(convertAuthMethod(AUTH))
        }

        // auth id if the auth is good
        // 0xFF if nothing is good

        socket.once("data", (data) => {
            let VER = data.readUint8(0); // socks version
            let CMD = data.readUint8(1); // command code (0x01 TCP/IP stream, 0x02 TCP/IP port bind)
            let ATYP = data.readUint8(3); // destination address type
            let DSTADDR; // destination address
            let DSTFAMILY; // destination family (IPv4 or IPv6)
            let DSTPORT = data.readUint16BE(data.length - 2); // destination 
            
            if (ATYP === 1) {
                DSTADDR = data.subarray(4, 8).join('.');
                DSTFAMILY = 4;
                onGotAddr()
            } else if (ATYP === 4) {
                DSTADDR = data.subarray(4, 20).toString('hex');
                DSTFAMILY = 6;
                onGotAddr()
            } else if (ATYP === 3) {
                const domainLength = data.readUInt8(4);
                DSTADDR = data.subarray(5, 5 + domainLength).toString();

                dns.lookup(DSTADDR, (err, address, family) => {
                    if(err) {
                        socket.end(Buffer.from([0x05, 0x04]))
                        return //console.error(err);
                    }

                    DSTFAMILY = family;
                    DSTADDR = address;
                    onGotAddr()
                })
            }

            function onGotAddr() {    
                let serverSocket = net.connect({
                    host: DSTADDR,
                    port: DSTPORT
                }, () => {
                    /*socket.on("data", (data) => {
                        console.log("client", data.toString())
                    })

                    serverSocket.on("data", (data) => {
                        console.log("server", data.toString())
                    })*/
            
                    serverSocket.pipe(socket);
                    socket.pipe(serverSocket);

                    serverSocket.on("error", (err) => socket.end)
                    serverSocket.on("end", socket.end)

                    socket.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));
                });
            
                serverSocket.on('error', (err) => {
                    console.error(err);
            
                    socket.end(Buffer.from([0x05, 0x01]));
                });
            }
            
        })

        socket.write(Buffer.from([0x05, 0x00]))
    })

    //socket.end('goodbye\n');
})

function convertAuthMethod(method){
    let methods = ["none", "GSSAPI", "user/pass", "challange-handshake", null, "challange-response", "secure-sockets-layer", "NDS", "multi-authentication-framework", "json", null]
    return methods[method] || null
}

let port = 50210;
let host = "127.0.0.1"; // 127.0.0.1 ||||| :: // IPv4 and IPv6

server.listen(port, host, () => {
    console.log(`opened server on ${server.address().address}:${server.address().port}`);
}); 