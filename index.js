
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
				privateKey: `MIIEowIBAAKCAQEAm6Hl88n8LuI6jkwRQu9z3zfNbltMvJmTrGht2sKT85eWJtoq
				+oCjtfog9Bpq/zKyGXYlMEWHQAyo7ub+MWeoZ+43pgVopV27e0yDl/jRvuIVUoKH
				7oDejLGAZJi4ZJDBt7K+Dn/ScZutsyeNO9GckP5YxV6042PIyyCHPUOyyH9BZZvW
				h+xUx/NLveOo/ypybE+uMFVLquAcRmKKWr9wTIfhnHwnk9UFytikqYJc8bVXBKhk
				37cZktD7VnH2KtRDbIDTLVqiLMZguan0TxF3M1qPTw6XrjNmrbiaiE0H/vuzMQE1
				5Iq4fLEpLOKzwRnd0rNAYjSWPEPiMmlvcgeKGwIDAQABAoIBAGiVOvnAWf8Hd2H4
				LAFW9/6geSQXplF2wo2w/2FqMBIZY4VoRklf+KNpGovu1Mf5QUVq50Kw9lpMJ5mj
				EF4S0lBE/JBMQi4d9sa8fBG72vby5nEz1jSn1OWmwijXl9G8lPDk5GLJ8pj1jJw/
				j+EK0rN8uBqpsdS8UUpu6XJ588JW9TZnG9avN6OLdx2EwGyl0u8X24E/1WTLHqSS
				GFssnBK/jd4pgjv7FTXJ6KzhWOEiNNeAXcOZzMzSG+3/fCFghR/uDjfYoheraETg
				9Ms6PY5/5t6qbCOLUpt9Kv+ph1b0dXkWA2J5faP66sywqzMN6tZF3H5Da4IRfawC
				9sAqywECgYEAzQQ2oydUCJrMcaIW1Hm/yiaTQ0PweErfAaEGLiVuyxXyK82Tm0FA
				byogks1mYzkAC9afLRPFh2ZiOfeo91ieqYIw0yoBEKoEPEhYtqICUdlpugN6VrxS
				Oz5eZf+Tt/eDBu2V94B2myJKpzdw+iLl6FXVmOcV3hjxd/ij2qABGcsCgYEAwlXK
				eLn0zVidO85Zj4x+y63jC/Ud9nVA1wg45WiUQ+6reFgklNjlrtnUffyabj562dd2
				m/zp/Rem7UTFH43qag+W7ZwqfvRJg3JtIhNHXRq2EYZx0zWLeZ0c4FXStYr11W7V
				Judr9WAGKQAeq8ju0irgbadMa+8R3rsMBIC6hvECgYAudF/1BDpUYM8miHXn21aL
				9cW0njZk64Iwmk4OMskyF1zyc/iYW2bASalr2kLzBL1v8UfMLQi7L4XeYLHWqiv5
				eNibYI8xOXUQO8xuRbOE3GDKl3MnKDDx36YAMrNEIj98WGV82Y0GhfSogzWEWFgE
				Fz75EJOx6bD9YEewiET3lQKBgHtEM7O0MGV4SfO/heuZ8Gt9lsDk7+Z+pWxAGObb
				GQCmCTnCnyGTGs13+mMXsVUwaHh5RRDYsgsJz6Y8stS7De/Mh62cGxCAH4kzMaol
				lGSoJsijANw54Ih5cfGSPp9Mz3ZcYPPWYxI3oHCtVMceIu5IqCalscHc2PbwqkTI
				6ofhAoGBALkCYRrHhBsQSb8mrovMYyv6lYfcC70gp+6cCV6oJcK4tSF41oYaQYJz
				wo1W59ohwpzVKVFBAsTJJ6EaZxTx/PL4dWJvmUEKRwo5LaGRctnMEF+EGjgSQNgU
				wSQ4CHnPQnhWOhKk5Az2o4SiZDBzFkGS3L5yQJv7Ip7mHPpKRUwZ`,
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
