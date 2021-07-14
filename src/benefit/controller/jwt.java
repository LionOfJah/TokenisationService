package benefit.controller;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.logging.Logger;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/*import net.minidev.json.JSONObject;*/
import org.json.JSONObject;

import benefit.service.FooSignatureGenerator;
import benefit.service.JweSample;



public class jwt extends HttpServlet {
	private static final Logger LOGGER = Logger.getLogger(jwt.class.getName());
	private static final long serialVersionUID = 1L; 
    public jwt() {
        super();
    }
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		response.getWriter().append("Hello");
	}

	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		SetAccessControlHeaders(response);
		String Signature=request.getHeader("Signature");
		String JsonPayload = request.getReader().lines().reduce("", (accumulator, actual) -> accumulator + actual);
		String result = "Error";String Flag=null;
		JSONObject object=null;
		try
		{
		object = new JSONObject(JsonPayload);
		String encryptedData=object.getString("encryptedData");
		Flag=new FooSignatureGenerator().generateSignatureAsBase64ValidateCrypto(JsonPayload,Signature);
		LOGGER.info("Flag:"+Flag);
		if(Flag.equals("Y")){
			result = new JweSample().decrypt(encryptedData);
		}
		else {
			String error = "{\r\n" + 
					"\"meta\": {\r\n" + 
					"  \"status\": \"fail\"\r\n" + 
					"},\r\n" + 
					"\"error\": {\r\n" + 
					"\"code\": \"UNAUTHORIZED\",\r\n" + 
					"\"description\": \"Unauthorized\",\r\n" + 
					"\"message\": \"signature verification failed\"\r\n" + 
					"  }\r\n" + 
					"  }";
			result= error;
		}
		}catch (Exception e) {
			StringWriter sw = new StringWriter();
			e.printStackTrace(new PrintWriter(sw));
			String error="{\r\n" + 
					"\"meta\": {\r\n" + 
					"  \"status\": \"fail\"\r\n" + 
					"},\r\n" + 
					"\"error\": {\r\n" + 
					"\"code\": \"CRYPTOGRAPHY_ERROR\",\r\n" + 
					"\"description\": \"CRYPTOGRAPHY_ERROR\",\r\n" + 
					"\"message\": \"Decryption Failed\""+e.getMessage()+"\r\n" + 
					"  }\r\n" + 
					"  }";
			
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
