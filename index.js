
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
				privateKey: `MIIEpQIBAAKCAQEApvGjAOwER74UFHl40q4jEu1Kmw29LDYukiDFJPp9LpilFfB/
				qS/foXAnXD2RCDC64TeIBdWQBgyTCRWEncKFT0Xhqh2SHtnI1khHeh01FDvXKwdJ
				gQWIGxQmgpDTlgG4BqPPg5aA6tuX/zyzyIk8qbJKGLSLL9B+G8QJ7reZqFJ4FY1J
				jyqAC5yZgrpPgPFUWYmAmDt3ReMVZEXA3ngWS7GqqetHwAGlhqFHnIB4TRos3rBD
				5CZeX2CSdX71+pNNw2yPwu2LO7TIUd712CMWqVQiuHCQp2Z52OiCW1wZPBne/cvk
				nsaSLYjip/8CHjs13XeRdvwJoXVYKVtpnWCl4wIDAQABAoIBAQCXxFZ2kRm3CvMA
				Rgn0JcDXBQfs+8l9duhRih8PZfUFtllmH5Q+/7mi7u2paoL92icadbxf6W2cQjQt
				bvV34g4FKjdjyqw7BawSOfVY61KEyX3rrR1CgP/h9iioS/c+iON+jc8qBlm+qNF+
				hPXAGhse/mlkGkXquvTaUxbggOLc5FezQKBQdz5wB6yryDPUIVwlnSbZvrE5c/ea
				ax924OQhtuMV5mpHhZ3tfDTi22tcpDXebJ6FqNVpKhkVX3kB3/yUYq7gkEV1FgxU
				G26sQHZVsMjxsEUYElI29wK8GFVcXeEyjPlhpxqqHS4kFxW8BCc552A55ULk+2wn
				rclOifaJAoGBAPGvXcZbD0nIL79u0rnivfo02keKHmRS2CpM0uAo3f/jW91kqSWq
				p4zerQHM75MCjFN86/Q7GOwLCVIbRUCNjQTsa2EdbAa0VB/k9sVj0R5h5KG51O4F
				zzBwYXShquwYw879ySl2UXtZKKQZuS3Fi76jYy0i3vFqJGfir82PAwIFAoGBALDU
				+10p1rvpDdikAerA72wtWZBYa52bZTc2W17SKDIyXxIoc0ic/FVkIN0Lqgxcplsi
				aZjWlrH4OB2W1GJDiNZH5eV0F4ctrNEzl8D6qNlUE4ceqmMeVrEFP6ebVbVCFmPN
				pIT2wiE1sxKvISpeRZHVH5WlcRKNRLARfA+jmgTHAoGBANmU8I6YAi6BjAMDCbGR
				4Ui1dmH7hZr6PmPun9Zw1FP/4v9xFRq1BXy8J/M8Bd9K5vxutZo97hTrZqvFo1YX
				WYK6OX3H2C49AJNqNYPFdkmtBgFXZMwY7MuGESbIOTGupfHe5tBuFbM/tGfwRJdh
				horNW4cSIrYiwb3JBk7AVovlAoGACeZSkDuoZuq8OLWt2culW8QKMJeSpsctWnLz
				mJJhZ7YENosHMTiAs/MgF9/wTDLfqVh62vCgjSQdWCK6jynCvmRWDYt7SbkX5Lpj
				s40U6N3ZHgZseZIYPl7R2ntKyBQEFuBLZpo98ggEl3YwgCO491ocI4+YjfZUsxq3
				fFSnab8CgYEAndsQk/y0rqcOg+jWRoHKRNWs5a/O/nvK4VJUIKd8T0B2aLtnu4/i
				K3RaZHOgzK/UBicuFeeAT9SYHyw5G9jatHjw3y/D6Zr50LIaiDe4v4/qKtfHRerr
				CM5t2CKpwlRYBjxeocizmB2BKQSLS2HzyKURB3IY13Qkrn1tHvLCdYw=`,
				keyVersion: 4
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
