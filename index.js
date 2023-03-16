
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
				privateKey: `TUlJRW93SUJBQUtDQVFFQW02SGw4OG44THVJNmprd1JRdTl6M3pmTmJsdE12Sm1UckdodDJzS1Q4NWVXSnRvcQorb0NqdGZvZzlCcHEvekt5R1hZbE1FV0hRQXlvN3ViK01XZW9aKzQzcGdWb3BWMjdlMHlEbC9qUnZ1SVZVb0tICjdvRGVqTEdBWkppNFpKREJ0N0srRG4vU2NadXRzeWVOTzlHY2tQNVl4VjYwNDJQSXl5Q0hQVU95eUg5QlpadlcKaCt4VXgvTkx2ZU9vL3lweWJFK3VNRlZMcXVBY1JtS0tXcjl3VElmaG5Id25rOVVGeXRpa3FZSmM4YlZYQktoawozN2Naa3REN1ZuSDJLdFJEYklEVExWcWlMTVpndWFuMFR4RjNNMXFQVHc2WHJqTm1yYmlhaUUwSC92dXpNUUUxCjVJcTRmTEVwTE9LendSbmQwck5BWWpTV1BFUGlNbWx2Y2dlS0d3SURBUUFCQW9JQkFHaVZPdm5BV2Y4SGQySDQKTEFGVzkvNmdlU1FYcGxGMndvMncvMkZxTUJJWlk0Vm9Sa2xmK0tOcEdvdnUxTWY1UVVWcTUwS3c5bHBNSjVtagpFRjRTMGxCRS9KQk1RaTRkOXNhOGZCRzcydmJ5NW5FejFqU24xT1dtd2lqWGw5RzhsUERrNUdMSjhwajFqSncvCmorRUswck44dUJxcHNkUzhVVXB1NlhKNTg4Slc5VFpuRzlhdk42T0xkeDJFd0d5bDB1OFgyNEUvMVdUTEhxU1MKR0Zzc25CSy9qZDRwZ2p2N0ZUWEo2S3poV09FaU5OZUFYY09aek16U0crMy9mQ0ZnaFIvdURqZllvaGVyYUVUZwo5TXM2UFk1LzV0NnFiQ09MVXB0OUt2K3BoMWIwZFhrV0EySjVmYVA2NnN5d3F6TU42dFpGM0g1RGE0SVJmYXdDCjlzQXF5d0VDZ1lFQXpRUTJveWRVQ0pyTWNhSVcxSG0veWlhVFEwUHdlRXJmQWFFR0xpVnV5eFh5SzgyVG0wRkEKYnlvZ2tzMW1ZemtBQzlhZkxSUEZoMlppT2ZlbzkxaWVxWUl3MHlvQkVLb0VQRWhZdHFJQ1VkbHB1Z042VnJ4UwpPejVlWmYrVHQvZURCdTJWOTRCMm15SktwemR3K2lMbDZGWFZtT2NWM2hqeGQvaWoycUFCR2NzQ2dZRUF3bFhLCmVMbjB6VmlkTzg1Wmo0eCt5NjNqQy9VZDluVkExd2c0NVdpVVErNnJlRmdrbE5qbHJ0blVmZnlhYmo1NjJkZDIKbS96cC9SZW03VVRGSDQzcWFnK1c3WndxZnZSSmczSnRJaE5IWFJxMkVZWngweldMZVowYzRGWFN0WXIxMVc3VgpKdWRyOVdBR0tRQWVxOGp1MGlyZ2JhZE1hKzhSM3JzTUJJQzZodkVDZ1lBdWRGLzFCRHBVWU04bWlIWG4yMWFMCjljVzBualprNjRJd21rNE9Nc2t5RjF6eWMvaVlXMmJBU2FscjJrTHpCTDF2OFVmTUxRaTdMNFhlWUxIV3FpdjUKZU5pYllJOHhPWFVRTzh4dVJiT0UzR0RLbDNNbktERHgzNllBTXJORUlqOThXR1Y4MlkwR2hmU29neldFV0ZnRQpGejc1RUpPeDZiRDlZRWV3aUVUM2xRS0JnSHRFTTdPME1HVjRTZk8vaGV1WjhHdDlsc0RrNytaK3BXeEFHT2JiCkdRQ21DVG5DbnlHVEdzMTMrbU1Yc1ZVd2FIaDVSUkRZc2dzSno2WThzdFM3RGUvTWg2MmNHeENBSDRrek1hb2wKbEdTb0pzaWpBTnc1NEloNWNmR1NQcDlNejNaY1lQUFdZeEkzb0hDdFZNY2VJdTVJcUNhbHNjSGMyUGJ3cWtUSQo2b2ZoQW9HQkFMa0NZUnJIaEJzUVNiOG1yb3ZNWXl2NmxZZmNDNzBncCs2Y0NWNm9KY0s0dFNGNDFvWWFRWUp6CndvMVc1OW9od3B6VktWRkJBc1RKSjZFYVp4VHgvUEw0ZFdKdm1VRUtSd281TGFHUmN0bk1FRitFR2pnU1FOZ1UKd1NRNENIblBRbmhXT2hLazVBejJvNFNpWkRCekZrR1MzTDV5UUp2N0lwN21IUHBLUlV3Wg==`,
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
