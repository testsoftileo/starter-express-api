
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
				privateKey: `MIIEpQIBAAKCAQEAvKJ87GCEdBrKuitRd7dLFMr15FO2MKMmOe/tw8S/uNyztW1IdBQsj1fHm2GShQCUfeF/TLKcTfvngl66n+5g7tHXYUbE6y+38pq/+eLQ0j0Kt+GXq0Nw6/5V5lHXsTBDUBbSdDzHGI35u6G+cuHdPoOYM1VPRUKGJEgwtoGlEBTpneoPiQytluNSqwfwShibplNgSJWPCBP6hxX1IkROsr61s1TjdBWHbWF+eYGn1G+FudHOQDJB41rGJ6za6sL91909ti/6fxyb1aDs08WwredJ1IzKdu2VIZHtC0stlTQlQVTQ1u4OG7HhrX/AFLcDsTuyi1pb4FRWeDm70yFKEwIDAQABAoIBAFLJFP5AVaEG6RXPUQ+zN5ZGhKfSPVEXKP2gWL7kKCgfZBcpgPTArdWy9n0w0zbfzEt6nX2xnXt0JGRI4qqx2YS2P0oH3wBAjwA//iTS8EZ0V7HfpcqZ7IMFufk8zeaLgd8yROaSjeYu2P0JvSV6DrkS08cjl4iT638c15QhTanCYbCtmyVWrdQxbSv+Uwx6aV5AZ3y+4Mg9kbvrXu5adDLUgSt76XgbkVw9BlIeBsWcscje3phBnXY15AtI87a0EzxrwFJOqT4/tuBOfRzEP2JHa/K2+jZOk5EmxWjqYeUxmSbBlooLwEVN8Xc7gACoa4TueZ7UdpzN6jsj0vTVwBECgYEA9fHe4N1/WRYaXAtv92KOcelY+dGuGzNWskc+JrV059bwLgDIxNZUookarZ5u9wgl2JzNmmyFcwL/KgzmBV9yizcOCjtrxsJUCTzFd6CFRFUOQRtM73xJb2sX0kC1z9IPz4EP0OXf2zKTMQoHHn7h2ABk3rP+/zOeb8O7+bAuoH8CgYEAxFjLHftf34FhC5SmfSSVxVVJq+69LbzLJk6SlmOcxSP3gjJsCIHCu3zZDFrvuJSTGBE1VrUSokSaQAs1o12RHswuqaTScnYD0rMDUey6jm6KVSk6nRKYPUi6qjN8+Keku3/7ikvbbUWGO6x85HslFDd4XnvScIwhKZMzz5+/DG0CgYEA4rgq22OUR41mkz8/4e8KnNudV/4A37Y9z255TrmroSS0l9PFQB7MOmDlJPOOG095g+tYZWhwxIsYqazmRkGsl8USvj/0pG7zhOhuqE5jS5CU6VO/Ym1STNGOThW1BHUCeijhaZLe/3Pp2CUEVwpkKviCBAItqRfuj90B5bSR5wUCgYEAufBYkhEOjsuoCl6Ad/xgdRq6hL62moyyWZmJCjBVMwBHkR2M31V7AzBNH30yjTruPZl2SKF7fv22kbXL2uRt3JuCCRdUUB7gqfTqzPeBCAc4q0M7BaqpT0gDtdDCpXuk7gdaP3Js3wM7BmHneDwCNi39qIRcGkcp1IRZSWK/etUCgYEAlJbLFEt+ObDs/RntWN4r60RbAJDcnZ1ApbL451GgydSskhtf5yTpQnfI6jgCWPov72V+yYaIfYwb7jzkMQdmh834Cx/+KDJhHkN/23hIvo2Eh/73RZF6kuSpsEYyhnUF+c7JVkl0GvXrWQlDwn8yQnrdj3bX2i73xFI4Ww3lO8c=`, 
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
