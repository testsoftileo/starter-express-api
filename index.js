
import express from "express";
import NodeRSA from "node-rsa";
import fetch from "node-fetch";

let app = express();
app.post("/getWalmartCredentials", function(request, response){

	let json_response = {};
	// if(typeof request.query['token'] != 'undefined' && request.query['token'] != '' && typeof request.query['consumerID'] != 'undefined' && request.query['consumerID'] != '' && typeof request.query['privateKey'] != 'undefined' && request.query['privateKey'] != '' && typeof request.query['keyVersion'] != 'undefined' && request.query['keyVersion'] != ''){

		// if(request.query['token'] == 'IEogIBAAKCAQEAjmk3KMwIEVhdgH67Fp4Sjs4qMqRXe9zpVcUc'){

			const data = {
				consumerID: "72508688-7d68-4876-9d6c-26de7e8ed3f0",
				privateKey: `MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCboeXzyfwu4jqO
				TBFC73PfN81uW0y8mZOsaG3awpPzl5Ym2ir6gKO1+iD0Gmr/MrIZdiUwRYdADKju
				5v4xZ6hn7jemBWilXbt7TIOX+NG+4hVSgofugN6MsYBkmLhkkMG3sr4Of9Jxm62z
				J4070ZyQ/ljFXrTjY8jLIIc9Q7LIf0Flm9aH7FTH80u946j/KnJsT64wVUuq4BxG
				Yopav3BMh+GcfCeT1QXK2KSpglzxtVcEqGTftxmS0PtWcfYq1ENsgNMtWqIsxmC5
				qfRPEXczWo9PDpeuM2atuJqITQf++7MxATXkirh8sSks4rPBGd3Ss0BiNJY8Q+Iy
				aW9yB4obAgMBAAECggEAaJU6+cBZ/wd3YfgsAVb3/qB5JBemUXbCjbD/YWowEhlj
				hWhGSV/4o2kai+7Ux/lBRWrnQrD2WkwnmaMQXhLSUET8kExCLh32xrx8Ebva9vLm
				cTPWNKfU5abCKNeX0byU8OTkYsnymPWMnD+P4QrSs3y4Gqmx1LxRSm7pcnnzwlb1
				Nmcb1q83o4t3HYTAbKXS7xfbgT/VZMsepJIYWyycEr+N3imCO/sVNcnorOFY4SI0
				14Bdw5nMzNIb7f98IWCFH+4ON9iiF6toROD0yzo9jn/m3qpsI4tSm30q/6mHVvR1
				eRYDYnl9o/rqzLCrMw3q1kXcfkNrghF9rAL2wCrLAQKBgQDNBDajJ1QImsxxohbU
				eb/KJpNDQ/B4St8BoQYuJW7LFfIrzZObQUBvKiCSzWZjOQAL1p8tE8WHZmI596j3
				WJ6pgjDTKgEQqgQ8SFi2ogJR2Wm6A3pWvFI7Pl5l/5O394MG7ZX3gHabIkqnN3D6
				IuXoVdWY5xXeGPF3+KPaoAEZywKBgQDCVcp4ufTNWJ07zlmPjH7LreML9R32dUDX
				CDjlaJRD7qt4WCSU2OWu2dR9/JpuPnrZ13ab/On9F6btRMUfjepqD5btnCp+9EmD
				cm0iE0ddGrYRhnHTNYt5nRzgVdK1ivXVbtUm52v1YAYpAB6ryO7SKuBtp0xr7xHe
				uwwEgLqG8QKBgC50X/UEOlRgzyaIdefbVov1xbSeNmTrgjCaTg4yyTIXXPJz+Jhb
				ZsBJqWvaQvMEvW/xR8wtCLsvhd5gsdaqK/l42JtgjzE5dRA7zG5Fs4TcYMqXcyco
				MPHfpgAys0QiP3xYZXzZjQaF9KiDNYRYWAQXPvkQk7HpsP1gR7CIRPeVAoGAe0Qz
				s7QwZXhJ87+F65nwa32WwOTv5n6lbEAY5tsZAKYJOcKfIZMazXf6YxexVTBoeHlF
				ENiyCwnPpjyy1LsN78yHrZwbEIAfiTMxqiWUZKgmyKMA3DngiHlx8ZI+n0zPdlxg
				89ZjEjegcK1Uxx4i7kioJqWxwdzY9vCqRMjqh+ECgYEAuQJhGseEGxBJvyaui8xj
				K/qVh9wLvSCn7pwJXqglwri1IXjWhhpBgnPCjVbn2iHCnNUpUUECxMknoRpnFPH8
				8vh1Ym+ZQQpHCjktoZFy2cwQX4QaOBJA2BTBJDgIec9CeFY6EqTkDPajhKJkMHMW
				QZLcvnJAm/sinuYc+kpFTBk=`, 
				keyVersion: 5
			}
			
			const { privateKey, consumerID, keyVersion } = data;
			const hashList = {
				"WM_CONSUMER.ID": consumerID,
				"WM_CONSUMER.INTIMESTAMP": Date.now().toString(),
				"WM_SEC.KEY_VERSION": keyVersion,
			}; 
			
			const sortedHashString = `${hashList["WM_CONSUMER.ID"]}\n${hashList["WM_CONSUMER.INTIMESTAMP"]}\n${hashList["WM_SEC.KEY_VERSION"]}\n`;
			const signer = new NodeRSA(privateKey, "pkcs1");
			const signature = signer.sign(sortedHashString);
			const signature_enc = signature.toString("base64");
		
			const generateWalmartHeaders = {
				"AUTH_SIGNATURE": signature_enc,
				"INTIMESTAMP": hashList["WM_CONSUMER.INTIMESTAMP"],
				"CONSUMERID": hashList["WM_CONSUMER.ID"],
				"KEY_VERSION": hashList["WM_SEC.KEY_VERSION"],
			}
	
			json_response = {
				"request": true,
				"data":	{
					"headers": generateWalmartHeaders
				},
				"error": false,
				"error_type": false
			}

		// } else {

		// 	json_response = {
		// 		"request": false,
		// 		"data": false,
		// 		"error": "Token is invalid! Please try again...",
		// 		"error_type": 2
		// 	}

		// }

	// } else {

	// 	json_response = {
	// 		"request": false,
	// 		"data": false,
	// 		"error": "Missing required fields! Please try again...",
	// 		"error_type": 1
	// 	}

	// }

	response.setHeader('Content-Type', 'application/json');
	response.end(JSON.stringify(json_response));
	
});

app.listen(process.env.PORT || 3000);
