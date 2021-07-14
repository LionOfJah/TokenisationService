package benefit.controller;

import java.io.IOException;
import java.util.logging.Logger;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.json.JSONObject;

import benefit.service.FooSignatureGenerator;
import benefit.service.JweSample;

public class JWTCrypto extends HttpServlet {
	private static final Logger LOGGER = Logger.getLogger(JWTCrypto.class.getName());
	private static final long serialVersionUID = 1L;
       
    public JWTCrypto() {
        super();    
    }
	
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		response.getWriter().append("GET method not allowed");
	}

	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		SetAccessControlHeaders(response);
		response.setContentType("application/json");
		String PlainPayload=request.getHeader("EncPayload");
		String JsonPayload = request.getReader().lines().reduce("", (accumulator, actual) -> accumulator + actual);
		String result = "Error";String Flag=null;String encryptedData=null;
		JSONObject object=null;
		try
		{
		encryptedData=new JweSample().encrypt(PlainPayload);
		LOGGER.info("encryptedData:: "+encryptedData);
		object=new JSONObject(encryptedData);
		LOGGER.info("executed"+object);
		Flag=object.getString("status");
		LOGGER.info("encryptedData Flag:: "+Flag);
		if(Flag.equals("Y")) {
			result=new FooSignatureGenerator().generateSignatureAsBase64(object.getString("CryptoData"),JsonPayload); 
		 }
		else {
			result=encryptedData;
		}
		}catch (Exception e) {
			result="{\r\n" + 
					"\"status\": \"fail\",\r\n" + 
					"\"error\": \"CRYPTOERROR\",\r\n" + 
					"\"message\": \"Decryption Failed\""+e.getMessage()+"\r\n" +  
					"}";	
		}
		LOGGER.info("result:: "+result);
		response.getWriter().append(result);
	
	}
	private void SetAccessControlHeaders(HttpServletResponse response) {
		response.setHeader("Access-Control-Allow-Origin", "*");
        response.setHeader("Access-Control-Allow-Methods", "POST");	
	}


}
