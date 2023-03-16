
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
				privateKey: `MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC8onzsYIR0Gsq6
				K1F3t0sUyvXkU7YwoyY57+3DxL+43LO1bUh0FCyPV8ebYZKFAJR94X9MspxN++eC
				Xrqf7mDu0ddhRsTrL7fymr/54tDSPQq34ZerQ3Dr/lXmUdexMENQFtJ0PMcYjfm7
				ob5y4d0+g5gzVU9FQoYkSDC2gaUQFOmd6g+JDK2W41KrB/BKGJumU2BIlY8IE/qH
				FfUiRE6yvrWzVON0FYdtYX55gafUb4W50c5AMkHjWsYnrNrqwv3X3T22L/p/HJvV
				oOzTxbCt50nUjMp27ZUhke0LSy2VNCVBVNDW7g4bseGtf8AUtwOxO7KLWlvgVFZ4
				ObvTIUoTAgMBAAECggEAUskU/kBVoQbpFc9RD7M3lkaEp9I9URco/aBYvuQoKB9k
				FymA9MCt1bL2fTDTNt/MS3qdfbGde3QkZEjiqrHZhLY/SgffAECPAD/+JNLwRnRX
				sd+lypnsgwW5+TzN5ouB3zJE5pKN5i7Y/Qm9JXoOuRLTxyOXiJPrfxzXlCFNqcJh
				sK2bJVat1DFtK/5TDHppXkBnfL7gyD2Ru+te7lp0MtSBK3vpeBuRXD0GUh4GxZyx
				yN7emEGddjXkC0jztrQTPGvAUk6pPj+24E59HMQ/Ykdr8rb6Nk6TkSbFaOph5TGZ
				JsGWigvARU3xdzuAAKhrhO55ntR2nM3qOyPS9NXAEQKBgQD18d7g3X9ZFhpcC2/3
				Yo5x6Vj50a4bM1ayRz4mtXTn1vAuAMjE1lSiiRqtnm73CCXYnM2abIVzAv8qDOYF
				X3KLNw4KO2vGwlQJPMV3oIVEVQ5BG0zvfElvaxfSQLXP0g/PgQ/Q5d/bMpMxCgce
				fuHYAGTes/7/M55vw7v5sC6gfwKBgQDEWMsd+1/fgWELlKZ9JJXFVUmr7r0tvMsm
				TpKWY5zFI/eCMmwIgcK7fNkMWu+4lJMYETVWtRKiRJpACzWjXZEezC6ppNJydgPS
				swNR7LqObopVKTqdEpg9SLqqM3z4p6S7f/uKS9ttRYY7rHzkeyUUN3hee9JwjCEp
				kzPPn78MbQKBgQDiuCrbY5RHjWaTPz/h7wqc251X/gDftj3PbnlOuauhJLSX08VA
				Hsw6YOUk844bT3mD61hlaHDEixiprOZGQayXxRK+P/SkbvOE6G6oTmNLkJTpU79i
				bVJM0Y5OFbUEdQJ6KOFpkt7/c+nYJQRXCmQq+IIEAi2pF+6P3QHltJHnBQKBgQC5
				8FiSEQ6Oy6gKXoB3/GB1GrqEvraajLJZmYkKMFUzAEeRHYzfVXsDME0ffTKNOu49
				mXZIoXt+/baRtcva5G3cm4IJF1RQHuCp9OrM94EIBzirQzsFqqlPSAO10MKle6Tu
				B1o/cmzfAzsGYed4PAI2Lf2ohFwaRynUhFlJYr961QKBgQCUlssUS345sOz9Ge1Y
				3ivrRFsAkNydnUClsvjnUaDJ1KySG1/nJOlCd8jqOAJY+i/vZX7Jhoh9jBvuPOQx
				B2aHzfgLH/4oMmEeQ3/beEi+jYSH/vdFkXqS5KmwRjKGdQX5zslWSXQa9etZCUPC
				fzJCet2PdtfaLvfEUjhbDeU7xw==`, 
				keyVersion: 6
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
