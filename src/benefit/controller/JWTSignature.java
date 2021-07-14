package benefit.controller;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;


import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import benefit.service.FooSignatureGenerator;

public class JWTSignature extends HttpServlet {
	private static final Logger LOGGER = LogManager.getLogger(JWTSignature.class);
	private static final long serialVersionUID = 1L; 
    public JWTSignature() {
        super();
    }
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		response.getWriter().append("GET Method Not Allowed");
	}

	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		SetAccessControlHeaders(response);
		response.setContentType("application/json");
		String JsonPayload = request.getReader().lines().reduce("", (accumulator, actual) -> accumulator + actual);
		String result = "Error";String Signature =null;
		try
		{
		Signature=new FooSignatureGenerator().generateSignature(JsonPayload);
		result="{\"status\": \"success\",\"Signature\": \""+Signature+"\"}";
		LOGGER.info("result:"+result);
		}catch (Exception e) {
			StringWriter sw = new StringWriter();
			e.printStackTrace(new PrintWriter(sw));
			String error="{\"status\": \"failure\",\"Signature\": \""+e.getMessage()+"\"}";
			result = error.toString();	
		}
		LOGGER.info("result:: "+result);
		response.getWriter().append(result);
	}
	private void SetAccessControlHeaders(HttpServletResponse response) {
		response.setHeader("Access-Control-Allow-Origin", "*");
        response.setHeader("Access-Control-Allow-Methods", "POST");	
	}

}
