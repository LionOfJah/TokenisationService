package benefit.controller;

import java.io.IOException;
import java.util.logging.Logger;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import benefit.service.JweSample;

public class JWTDecryption extends HttpServlet {
	private static final Logger LOGGER = Logger.getLogger(JWTDecryption.class.getName());
	private static final long serialVersionUID = 1L;
       
  
    public JWTDecryption() {
        super();
    }

	
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		response.getWriter().append("GET Method Not Allowed");
	}
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		SetAccessControlHeaders(response);
		response.setContentType("application/json");
		String EncData = request.getReader().lines().reduce("", (accumulator, actual) -> accumulator + actual);
		String result = "Error";String decryptedData=null;
		try
		{
		decryptedData=new JweSample().decrypt(EncData);
		LOGGER.info("decryptedData:: "+decryptedData);
		result ="{\r\n" + 
				"\"Status\":\"success\",\r\n" + 
				"\"decrypteddata\":"+decryptedData+"\r\n" + 
				"}";
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
