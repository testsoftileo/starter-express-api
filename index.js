
import express from "express";
import NodeRSA from "node-rsa";
import fetch from "node-fetch";
// let express = require("express");
// let NodeRSA = require("node-rsa");
// let fetch = require("fetch");
let app = express();

app.get("/", function(request, response){

	const data = {
		consumerID: "6368d199-ccb2-4d47-9765-6b559e729b6d",
		privateKey: `MIIEogIBAAKCAQEAjmk3KMwIEVhdgH+67Fp4Sjs4qMqRXe9zpVcUc9Grdb08+8OQ
		oGxC3wd4Uf3Igx/NtNzlBgdTAtNPsgIsFM71DRAvTtWs/rVAq8GhPAKucUj+HgoO
		PR0P+qMcfZnsneCBtU6xHF5FSDuPY9RejO6YW/LJNb7f+jf6gszxgfLi9Yr93asL
		/mbsi7bfDY4m5Ksd1W8XxObgVoHtQ7AQbfWYfRVcwgxFsEjI6uWLHFvzfGwxSy8K
		pAg+i9NQXrs3KdA+JHcBCNccpgRV9kZ9nJX+aJTkodJ775n7dxTsPdsfEnVnprmL
		X1QMA/6gTLg3I5wUpZQAH44TOxXqbVi41tmbGwIDAQABAoIBAHUCzmee/SIDURA7
		4wJAc4XKkwtdJYPhM0wu+IcRR6g+DNVwIm0thuRp5tq3gwD6KLLqrOL/MZ2oslq4
		ni+avI43Nie4OaQumSyGtEvyiBJcvy8/Y+Oi9XYif05UIq61wN2QAsYkTxjCl1aX
		L/jsMhOasOiQJMgbJqJCck0rnH/SqQOaYqiKvUTGrHLWQQK5+mv1AK5MqpHtzK7H
		pG8yb8kZLDHLmL5Gafk63SNR0cut49P8OWMq/V/fHROsQjwLznVtJT6/BxOBfSDJ
		ysxinrMPwaSLehxg73MhkhA234/CNExkInmtC+P8gZjgGBSLQAQ6ReK+DdPN4Qq7
		RGJlfQECgYEA889AXwPt9ob/h78MAFFuuwRv5m2Ly8DmD97qMrGEi+RYoNL/217f
		BnHzGJs1L4eJo1GmOSvQc9CkI/iKkhnWFJtR8PLtciB+IcgYRRy8Sz1k++IQ1OLw
		tEejbCPhVQjWb/hDKGhYFMWPDE9ejt+riTMQ/4vCrzqZMaoZypuduYsCgYEAlYgR
		a6lvxHa4Zm/GP9zHB5+Ex9JxcI4J3OCgMr7OFSzfA8OT6i0OvtxrGH0zcbQAkKDN
		oeSqzRNchfQfbQAWto5gTjaGVZT2gyBD/x3GjfvEcZI+oqNo1P2w/aPNhRcdQXjf
		NftvtjPcXSiV711xpR8/JDC85bk72jqSpTgbNrECgYAmGDv2nKaR3oYOr8swQYkL
		r6XMW1F8hKdt02bEhPgw43z1pAJWRHyUhTl2nsmwo3zeB+PxCueHMRJ0jGEacu8A
		SUSEYXC4ZFtQ6/Le2Z6SIwWkVa5LlSoHASqHuxN6NedLl37m0Wbx1+yB/+TGbixf
		Q5tkUnIY7w8As5NUFPyQAQKBgGJ38SjZsh1JJNNoJcAmTfaKKHFB9qvtDTejwDrK
		hYFSRCYBY+Vg+IXdNrUwtXDZ3UlgaymCIKvdZR9dDFjGJy7egTLgGwQ+jTr6Q2y7
		meYj9k/nw1FslHs1+Jh+hrdu6jgUNcEhq4XrjuDV+i5fdZgMBJN7eNk6atyhl7Iv
		SVRxAoGAF/UjyiODGj4nWye9Efwsj6ktALaCvmh9nzDrpZoCzSHFVBUJBL0RHd7V
		78FjNFRI8sIb67XhmKye/6KCUydefZGsZ1WPxf2SUR4VtmDhrbBMK71S/K+IO2Zt
		F+nBtgseAgl7yRFsQrcpd3fLtfaePu2xQXlg2Cga2PH/4fwK29g=`,
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
	
	console.log(generateWalmartHeaders);

	response.setHeader('Content-Type', 'application/json');
    response.end(JSON.stringify(generateWalmartHeaders));

	// fetch(`https://developer.api.walmart.com/api-proxy/service/affil/product/v2/items/2608995260?publisherId=${keyData.impactId}`, {
	// 	method: 'GET',
	// 	headers: {
	// 		"WM_SEC.AUTH_SIGNATURE": signature_enc,
	// 		"WM_CONSUMER.INTIMESTAMP": hashList["WM_CONSUMER.INTIMESTAMP"],
	// 		"WM_CONSUMER.ID": hashList["WM_CONSUMER.ID"],
	// 		"WM_SEC.KEY_VERSION": hashList["WM_SEC.KEY_VERSION"],
	// 	}
	// })
    // .then(response => response.json())
    // .then(response => function(response){

		

	// })
    // .catch(error => function(error){

		

	// });

	// fetch('http://thedailyfinds.local/users.json')
	// .then((response) => response.json())
	// .then(function(data){

	// 	// console.log(data);
	// 	response.end("data");

	// });


	// fetch('https://www.google.com/', {
	// 	method: 'POST'
	// })
	// .then((data) => {
		
	// 	response.writeHead(200, { 'Content-Type': 'text/html' });
	// 	response.end(data);

	// })
	// .catch((error) => {
		
	// 	response.end(error);

	// });
	
});

var server = app.listen(8081, function(){
	
	var host = server.address().address;
	var port = server.address().port;
	console.log("Example app listening at", port);

});
