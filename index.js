
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
				privateKey: `MIIEowIBAAKCAQEAuJEnP0/Ctl7uSsN4CTjOoIP52MxhuHV2lm7wIxd8seufcEYr
				iagIoEAD6Qp39JzzMW1yB366GDyK+6NCExmMlH+gy5CPv/W9rBpjVtYXt3rHsNyB
				f9KkE/ZIKe3nHqhlFFN21aBJisXAfQeL0x6jMzzV3TSB6b1zRDAfVTn3oB0RNVeT
				V2qGJkq582DrJnzIfrkRV91Lnt8uwc1AsSH5JZIp7KpWM48gfMpe2St7SK8DARCS
				4gQ/CHuXfA/UiVfO8qgEK3kP9ybStfgzSnAcIJ6i29AEWcvantAUrYIa9sohDXXs
				M4vEATJ/muyGIdfki4MR9OMrwkmDGgyB34NkbQIDAQABAoIBAAIFpRZue0WgOKAd
				EB2Zv7nGeGBFrPRmZQw03vCjezw/xplmS2fQrXeD/Ab7lGDbr1ZlSpCGdOd7ElK7
				cSfgacfethZE2S5TNObDyz7STaQ29iUb5VdPKXkGg7fh4VxWn/TfDTg971BT5k34
				XTHM7iDLk9Q+lQXIi5C9rjoyzmG0qw35SlSqlYwl312JIAWGiI9Z0Rl7dRIVCRdF
				rMQs8w7BudgDEGG0r3+Pm86M+1VATYWv9BEzpGClwvKGymFngzis6PsjG+cbPLtT
				DNgSYe9pzZiiNhOdM5B2S6/xCkgmEQtWFLS5ZlbYn8JY8cRibQd/R2oNpkvalIJH
				98EBwkkCgYEA3mcK0iIpwJjAe77i/KW/GsChrH0gQDvJZtTnb4u47Sgfnx/zw9J8
				70DKmbP4LzTNORepEeFXXCzIjDbEG4dG7fvybDXJlSf28jFprGiSZbf78xuvgKMv
				2EB84hj8Q0aXh0HSBJRXy6WtNqck1OnMGWP69QEqTz5aGA/rrFpbdNcCgYEA1HLm
				rIs1/8PxGgxiR2hMRD8G1Q9PB/xcrAFN6ihdMpoMWx2ulmId4rTUfzSbczb0Daiz
				Ld9Df6KaOvH1HXwK82/jWp3xbS8MR7dDl5ixf5LNHLKlnAVOkz7/tmrndNuScVy1
				t47DorLjMoACH/zKZew8M0vEJW2EUzNRT9MOhFsCgYBTtxvGn19yBM2nhuHwUf+O
				dWYmBG+IXjjggVGglkqE0q6cei2Kz4eBk7TviGPqeQiq7fIRLe5xXtYamV7WMeSM
				HmNRQingAEwfPGRXpoE80rV+/DPiywpub0/S167VMBRHsIn6eVBW8sUxplbh4iOW
				hyDm6opfi8vj9NI0bUqxvwKBgBCaklC16Jh+td81TJEMI7nJuzz3n1Oec5e12mMM
				mIwV4hVU8ooqTO+k9l6iu+t7RgOzRZ22L05QZQFqW5/cS/bOrdQtN+synCEWv5+f
				fW/dB07Q34ScHZIAgHe/Tyug5YcamdEoxT14Aa22t3PMi/z/Q402xLOwJYFjJ123
				vxC1AoGBALrGpYX6+3WUSBL/nNQOdZkUlX7n+2BPzlxB/8+JLbxmhlngwl9N2LjQ
				HQHdOAl8mfhdKHfiebyzJWI9iGCd27fYwyJ5n0s1Egk2hiBrJ3S/Pl4UPmLIPf4p
				1bjbXvZXRJqUytwMWTnY/8okd2aklwQVQoWlLPLULL305bcEPBar`,
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
