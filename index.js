
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
				privateKey: `MIIEpAIBAAKCAQEApW0c7A+p8gYMEwMVbkHgxJUgviifJ6dvjmQ0W7p9+dUmFut2
				5hEVlRKLdmlsKl0R1U7dw3FLRo084TKYw0kPnOaljcVmqnDkSSl4gmJW21deAsTX
				jpO0rvYCMGRikCEKHVBCcguafIbMMX+NP5KB24JB91bgpIomycXfMzvf5YeZVKXl
				7jGgjb0AEgsb3ILkumZfKV864UfcpgPPxsBWQBlH2iokj95TP8GJ0fLGM1I4ljqF
				3VTXGzsBLNfilvjo7O1E/QqZq6rEWOarvL02Mt+716XY96EcVUxSRb6harVyc8/a
				vGNb/wIqqn+lqeG7gGNiEf85R084EzcZF+LHWQIDAQABAoIBAHayQ/5dfuNZ03AQ
				1l+2hUCIgGXxX8FkMndJDwiCV8HbXukzKq0JtSKxm7/rBOGgxhr368dAk3KcBQLQ
				+yukUL+T/1YqPfAt8J9OUlm7lfbsSVhTRRfYg9zGR+vRG6evDULbQ9Hw4XhYgEtD
				6mWjCeonHI4MmEN3nT1J7U0luRFHgHZ4QI+EO96/YNUIsDfwnSTdLKFveIgVIpP7
				kd/V4F05aIrb6OWxm90sOfuROjGyxwOlkpqG+52HxFm9X0QPGFm9l6vbBUzL4hKi
				NMOBE738fphqpzKWBfvIrmJOJLpNVi/7lqWjlOIEK9hvrtaWFwgVdcahyyf+JMhg
				RwTD6AECgYEA6/kt38r+/4n+Lv4pFVetgz1w5ASxB7/Q8cHi6MBlu2Clzw+WIMS9
				UDft5fVEEBTrCVKKyy1GPUt7E9jdlpDqgn1G8hw+qeVaRAUOgtfEeULJoHLXCUzI
				/u0xqAy6ymsIOSrffff8DeeU/PjChBHwDm4t6n2w1IKRtOmO6eMW6bECgYEAs3c1
				LTSBZYGM0i+eDi4/RawGuDYJFSArsDheXcXxCIU+p7em+68ceVM3Ew1QFagLaowt
				Cd15LujnjKJGdt8K2TETi4gcEQGJ/xKUcHaUF8r6g3T1fNiW07TZt31pMO6BfqJ4
				/kCPDfPAX/jXIsdjnyT0lgADYw9s3wW+DQipeikCgYEA3dHAw8yo5EIthLM6n2tq
				GiKZil62o1g26+uch7rEZt21P+2g7HDEnTHWGgLy1kMzpfHHsrJ+goP/0Gpd8nmL
				WNq25ESUy1RkA+jU+T4m3O5hZshNR9q8XpdNxHEi7cCrXEHnER0Z/WAid6LIBypt
				hMMhunoozbtniK68vzPPiCECgYBbkaR5V0P6pdpTWGZ998zi4L5g+Xky5UJFXM2R
				bTDp1wq8CrHR02xk3zfHqdBF7IM+rx0/3lg5vi5/DEGF35IqdabyV9VyO+XMVw+U
				Pnybkz61GlUziVOT28AGpp+ojtlV4tJ3cDtNtCRhE5e5sCC9j96YNpOD1NgJB2YM
				QnIu2QKBgQCqplBTjXfnHo+ToEOMpmwwW+txwxxMvj2s2VgA6tQivcpFsdVoKfFm
				NCTuxbR9e3xd71F8in6sfNMuaTI1Uk8A0R+FnBg3GmLGxvPDDKoTJr5RgHwtH+Hp
				HfsxhLoMQRQ2spKzZZhyrHINXYmFJbnsqXvB1YdnbL4exUlzh9v5+w==`,
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
