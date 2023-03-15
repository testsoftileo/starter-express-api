
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
				privateKey: `P2/56wAAA+4AAAA3aWYtbW9kbntzaWdue3JzYS1wa2NzMS1zaGExfSxlbmNyeXB0e3JzYS
				1wa2NzMXYyLW9hZXB9fQAAAARub25lAAADnwAAA5sAAAARAQABAAAH/iYJYuqI2SPyr/7K
				wnhqHpDs6n9AF8G9TniDxz40RKwA4LpNSNiSPJDeMp0h1u5HaUnVlpQ+0AiOQ3RnPEa/vb
				M2Qd2pcDSuiAmC2MZ9q5kVG2L9ATsllUNs7yEiyUS0nImvs3tbiiAgQAaqIwjJLVZPJT5a
				NYpF/X5+i4Gwuh44h/Og9yuExud9SuNF7DpDBBTTCYjXBs1Rg71ZKE9LSPosRKtg8xnNrr
				axp7DbqKeCYOUsJFdHxWNJOYi+3Wn6OXphz0qpzDw9hHlrw+jeYEbYw131xdky20WENXmA
				LQwTd2v9fqGebeaizn0GGHj4gJUnqJJvse5yJFRloFYol4EAAAgAoqGNbTk/R0dqHMXEMe
				nv4kNDiyIN7RyYrojQd6QfiXIMvwgRvAsKvaQiIGiNXPdO2gkXrg1uwOgmhlMeKZ7OFBub
				20/dOsSfIdoXq+6qVYX0HDLXyRDXiFIUi0FgU1aZ5GnF7hRmiphR4sZxFZTyGIabNwnzyF
				fHbG0xtR1TFsO5avNtEda70s/xQm+RidpY9L0X4S9OxL0RyWQlD1I4Ov+niZ9s0rFfZfoQ
				iCAtHS9BUksUIAYYpD/rPXwCQlm7p3gb1S+4q2lYOW+v//N9sFe3NakZJAteGdmls/C05Y
				yHc2iK/Nc8zOudXN65n5BD3W7webH/yeVEVWss+WW6SQAAA/4mOhhiEoWL/nngM+39XBBC
				BThjAThgW1y7cqNFkZjQs+BglPk+y67QlRLJlEipnt7sTYtvU3bWw5P37kndr46b1AaFTZ
				0SGdHRebGXImMsnMnlkJ6tREf8ymuxFVIA0B5a5Xqzp7R90HulEAf20cY4nZZT66UFtjaQ
				+ewgaG2rnwAABACsPam1fQ7i4Op2zW2mLNdlQnlfYFLmk4gT0wfUKAS1OQ8pM11ggJvffi
				g6x00fy8AJOxVbIBHxSYQCQnsFd1kWAV/FS/+iBEV5cSIwwOwxD4kO7J5/Vk2QAHkPLRIL
				L0mc7s12ehkRB540jWO6Ha3zsFIurNadawwLV6GBCeQgiwAABADxt4+Mne8WvGGykISZlw
				L6x8ptv+qTaOr0GBUj3myjhIYobjbZosW5jX30LLoKl8wSjaOo6MUtlUd0K8P1Kb0/wn/b
				8HOUrnWg8B1xAYdp73y3Z56UNYvCd/upRU5AwXnn2tY579GvsciDiR/IeZV15NMKlWdWG/
				mCosP7GqW2+w==`,
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
