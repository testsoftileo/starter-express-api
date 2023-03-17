
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
				privateKey: `MIIEogIBAAKCAQEA1tRVVqnWOicexy2o6xutv33/A8uVWUUcJQTePQlZFOCeJWkz
				mj2gk54WbUw8g4lyx66WjKZqJI0o///q+uXYnYmnVMevd15+hnh2teLnSP3k7+8c
				kxI8tGtHS6Kp1ew+JwHSc7I0eMQ6TNO7mB49EIh24qy5uSmWU54NtUSb2+Yuzy9x
				yatzZpDM24dkYEo23R3N8WKZaFlJQD6NHhMGbppuIcR+oyDdap3IA2zWD9hqp2F3
				RlLDe/TL8ljMGl9oaCdN10k3CUmO8hrXC2yG9iZNa48B/KnlEa2hQ414vnj+9cOc
				z2DG362s7nEcotZ3JFbHGORDk1ilPaNtqaLuPQIDAQABAoIBADccCThOITKRzodx
				4x9M3ml9POoQU6Ou4uVsNkaaG0wLwwX90ssCfCriJwaqw+tKWzN2ShCSsC/oNlhV
				okXyqHrhUReikhShHPwJ8wn9xy8mUpBqWn4v83qk+okglUjXbao8AWzEjklcrUgA
				GOOQ/kE7gKPtg0dIr9OLfCDAFOt3zMBqObGpG2qASfx2/qNOoIx1uIFRphJvkYa0
				yAhKobD32bU2/Sld+kzBRPmlbC0A+9XN47cArBXl4yYcmY+Y5/Wy06iJOlPJxUsG
				jo4V5mz+8wRUQp9Bke+unezDWsZKm1vgbVvbG9i26HuC2tLA66o3E2GLRaIKk5mO
				B8xQnoECgYEA6tQ5sXk+IaX0LIzyzbNhvpqceCu42uaO3PsSXQEw1xK9kSas9Mbx
				riFPqrwHWOQcuzUhywPmJTipq/UL4eDeSmAzdor2qw1jxSKefKsqWcXwQvsEJfXg
				gKUjQ8kUm9fogm45ivdBcyQ+BW6VGgmw0fTQBamw4YSm8fF8b8/ow+UCgYEA6jKG
				QYDtwoAsuqtEz8XciKh+Nsi8kwRLH7vo5yCuI3zaFOEDKKTkZMicek2iL/Zb/BaN
				+oOHrPazcifRlFcRifubQkOJv2Am8cEsqP/ky6EN5tGkZXG9YAT8qqjN5hKkMh80
				qBoj9e9pDtMxXmygZpWg+6dhE8T9wCWxqRcti3kCgYAi5XTJXdYQ1AOMF0oBrXWK
				CJnV9dFbnkV+q0TYU1P5sgw/pLqxCVti4Aphud1xpTxryYKDE8pAn8H/DsQ8Rdli
				vhcHt7DeTHgWFIXuytTZUGPa4EiGh5pcI64w5ZHNcvFXaJ/eec3dGXaqAfvgSa5g
				FPxQyx3A9aCFdbhjOUdCzQKBgBdLtU0YvQ3G4CwlUy/zt48ka4GZkCBzoeFjOLSc
				7JV9GthO1ZiaZlmcFuyXglWRBO9bcv4DTWCoHYtyaId/7a+zBmud+jq+HsGXfJDG
				+4RB3fcizV6F5NeDR3rWVbzYB9swfXVnPEJ/cQzXdya0WXQ62AuQR7jGtJMDbNus
				AYzJAoGAFKHUa7LuM2HQ2qvBc91zGTeQTuw3XAgRuuhm9Pv2xMv7oY8BZxQoiCPx
				ZurJ7QIE3OwY7WgPAUptvqx8kVflD0PHOyivzhX2X+KSPylaG/HxYIK3RdgOQlyT
				xkWGBPPp59oUDohOtg0/V7UrtC8M194xsgemFBRUXuXoXI/Dvnk=`, 
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
