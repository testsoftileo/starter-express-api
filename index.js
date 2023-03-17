
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
				privateKey: `AAABADccCThOITKRzodx4x9M3ml9POoQU6Ou4uVsNkaaG0wLwwX90ssCfCriJwaq
				w+tKWzN2ShCSsC/oNlhVokXyqHrhUReikhShHPwJ8wn9xy8mUpBqWn4v83qk+okg
				lUjXbao8AWzEjklcrUgAGOOQ/kE7gKPtg0dIr9OLfCDAFOt3zMBqObGpG2qASfx2
				/qNOoIx1uIFRphJvkYa0yAhKobD32bU2/Sld+kzBRPmlbC0A+9XN47cArBXl4yYc
				mY+Y5/Wy06iJOlPJxUsGjo4V5mz+8wRUQp9Bke+unezDWsZKm1vgbVvbG9i26HuC
				2tLA66o3E2GLRaIKk5mOB8xQnoEAAACBAOrUObF5PiGl9CyM8s2zYb6anHgruNrm
				jtz7El0BMNcSvZEmrPTG8a4hT6q8B1jkHLs1IcsD5iU4qav1C+Hg3kpgM3aK9qsN
				Y8UinnyrKlnF8EL7BCX14IClI0PJFJvX6IJuOYr3QXMkPgVulRoJsNH00AWpsOGE
				pvHxfG/P6MPlAAAAgQDqMoZBgO3CgCy6q0TPxdyIqH42yLyTBEsfu+jnIK4jfNoU
				4QMopORkyJx6TaIv9lv8Fo36g4es9rNyJ9GUVxGJ+5tCQ4m/YCbxwSyo/+TLoQ3m
				0aRlcb1gBPyqqM3mEqQyHzSoGiP172kO0zFebKBmlaD7p2ETxP3AJbGpFy2LeQAA
				AIAUodRrsu4zYdDaq8Fz3XMZN5BO7DdcCBG66Gb0+/bEy/uhjwFnFCiII/Fm6snt
				AgTc7BjtaA8BSm2+rHyRV+UPQ8c7KK/OFfZf4pI/KVob8fFggrdF2A5CXJPGRYYE
				8+nn2hQOiE62DT9XtSu0LwzX3jGyB6YUFFRe5ehcj8O+eQ==`, 
				keyVersion: 8
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
