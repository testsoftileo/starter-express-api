
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
				privateKey: `AAABAAIFpRZue0WgOKAdEB2Zv7nGeGBFrPRmZQw03vCjezw/xplmS2fQrXeD/Ab7
				lGDbr1ZlSpCGdOd7ElK7cSfgacfethZE2S5TNObDyz7STaQ29iUb5VdPKXkGg7fh
				4VxWn/TfDTg971BT5k34XTHM7iDLk9Q+lQXIi5C9rjoyzmG0qw35SlSqlYwl312J
				IAWGiI9Z0Rl7dRIVCRdFrMQs8w7BudgDEGG0r3+Pm86M+1VATYWv9BEzpGClwvKG
				ymFngzis6PsjG+cbPLtTDNgSYe9pzZiiNhOdM5B2S6/xCkgmEQtWFLS5ZlbYn8JY
				8cRibQd/R2oNpkvalIJH98EBwkkAAACBAN5nCtIiKcCYwHu+4vylvxrAoax9IEA7
				yWbU52+LuO0oH58f88PSfO9Aypmz+C80zTkXqRHhV1wsyIw2xBuHRu378mw1yZUn
				9vIxaaxokmW3+/Mbr4CjL9hAfOIY/ENGl4dB0gSUV8ulrTanJNTpzBlj+vUBKk8+
				WhgP66xaW3TXAAAAgQDUcuasizX/w/EaDGJHaExEPwbVD08H/FysAU3qKF0ymgxb
				Ha6WYh3itNR/NJtzNvQNqLMt30N/opo68fUdfArzb+NanfFtLwxHt0OXmLF/ks0c
				sqWcBU6TPv+2aud025JxXLW3jsOisuMygAIf/Mpl7DwzS8QlbYRTM1FP0w6EWwAA
				AIEAusalhfr7dZRIEv+c1A51mRSVfuf7YE/OXEH/z4ktvGaGWeDCX03YuNAdAd04
				CXyZ+F0od+J5vLMlYj2IYJ3bt9jDInmfSzUSCTaGIGsndL8+XhQ+Ysg9/inVuNte
				9ldEmpTK3AxZOdj/yiR3ZqSXBBVChaUs8tQsvfTltwQ8Fqs=`,
				keyVersion: 1
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
