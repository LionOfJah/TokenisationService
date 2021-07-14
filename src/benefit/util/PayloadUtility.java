package benefit.util;

import java.util.Random;

import org.json.JSONException;
import org.json.JSONObject;

public class PayloadUtility {
	public static String generateRandom() {
		int randomNumberlength = 16;
		Random rand = new Random();
		long x = (long) (rand.nextDouble() * 100000000000000L);
		String randnum = String.valueOf(randomNumberlength) + String.format("%014d", x);
		return randnum;
	}
	public String getPayload(String cryptoData,String JSONPayload) throws JSONException {
		//String RefID=generateRandom();
		JSONObject js = new JSONObject(JSONPayload);
	    js.remove("encryptedData");
	    System.out.println("JSONpayload1"+js);
	    js.put("encryptedData", cryptoData);
	    System.out.println("JSONpayload2"+js);
		return js.toString();
		
	}
	
}
