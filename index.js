
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
				privateKey: `QUFBQkFHaVZPdm5BV2Y4SGQySDRMQUZXOS82Z2VTUVhwbEYyd28ydy8yRnFNQklaWTRWb1JrbGYrS05wR292dQ0KMU1mNVFVVnE1MEt3OWxwTUo1bWpFRjRTMGxCRS9KQk1RaTRkOXNhOGZCRzcydmJ5NW5FejFqU24xT1dtd2lqWA0KbDlHOGxQRGs1R0xKOHBqMWpKdy9qK0VLMHJOOHVCcXBzZFM4VVVwdTZYSjU4OEpXOVRabkc5YXZONk9MZHgyRQ0Kd0d5bDB1OFgyNEUvMVdUTEhxU1NHRnNzbkJLL2pkNHBnanY3RlRYSjZLemhXT0VpTk5lQVhjT1p6TXpTRyszLw0KZkNGZ2hSL3VEamZZb2hlcmFFVGc5TXM2UFk1LzV0NnFiQ09MVXB0OUt2K3BoMWIwZFhrV0EySjVmYVA2NnN5dw0KcXpNTjZ0WkYzSDVEYTRJUmZhd0M5c0FxeXdFQUFBQ0JBTTBFTnFNblZBaWF6SEdpRnRSNXY4b21rME5EOEhoSw0KM3dHaEJpNGxic3NWOGl2Tms1dEJRRzhxSUpMTlptTTVBQXZXbnkwVHhZZG1Zam4zcVBkWW5xbUNNTk1xQVJDcQ0KQkR4SVdMYWlBbEhaYWJvRGVsYThVanMrWG1YL2s3ZjNnd2J0bGZlQWRwc2lTcWMzY1BvaTVlaFYxWmpuRmQ0WQ0KOFhmNG85cWdBUm5MQUFBQWdRRENWY3A0dWZUTldKMDd6bG1Qakg3THJlTUw5UjMyZFVEWENEamxhSlJEN3F0NA0KV0NTVTJPV3UyZFI5L0pwdVBucloxM2FiL09uOUY2YnRSTVVmamVwcUQ1YnRuQ3ArOUVtRGNtMGlFMGRkR3JZUg0KaG5IVE5ZdDVuUnpnVmRLMWl2WFZidFVtNTJ2MVlBWXBBQjZyeU83U0t1QnRwMHhyN3hIZXV3d0VnTHFHOFFBQQ0KQUlFQXVRSmhHc2VFR3hCSnZ5YXVpOHhqSy9xVmg5d0x2U0NuN3B3SlhxZ2x3cmkxSVhqV2hocEJnblBDalZibg0KMmlIQ25OVXBVVUVDeE1rbm9ScG5GUEg4OHZoMVltK1pRUXBIQ2prdG9aRnkyY3dRWDRRYU9CSkEyQlRCSkRnSQ0KZWM5Q2VGWTZFcVRrRFBhamhLSmtNSE1XUVpMY3ZuSkFtL3NpbnVZYytrcEZUQms9`,
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
