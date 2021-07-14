package benefit.service;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import com.nimbusds.jose.JWEObject;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import com.nimbusds.jose.Payload;
import java.util.Base64;
import java.util.logging.Logger;
/*import java.io.*;*/

public class JweSample {
	private static final Logger log=Logger.getLogger(JweSample.class.getName());

	/********************************ENCRYPTION*************************************************/
	public String encrypt(String JSONPayload){
		log.info("In JweSample.encrypt()*******************************");
		Security.addProvider(new BouncyCastleProvider());
		String temp_PublicKey = "-----BEGIN PUBLIC KEY-----\r\n" + 
				"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyBerz8H+BC8LeRDZi0+K\r\n" + 
				"62rImgbZz041XlIUipOH/OV4161HEPlabxLJHEr9Xh62CFxXILob+bOtNemIevSs\r\n" + 
				"RBpudYhKHZ+F9oZ3Fe0XdNpdhK2mrg47M1fREuXZnz365dD1SCuWuzr2XesWQ2AC\r\n" + 
				"SEeYN1MWofWSnOh2RokVmTiWyFdic25xxOOIr3WoQh7Z3/1aCLEaD2gH5Zy9CnVd\r\n" + 
				"VxCW/dbqK/0WG/hKBflSD/zLXTjMOhLkXAKpraaaDXBsTx1QTrcotYwl55i0aODA\r\n" + 
				"ZgzFJBzRZjXuzsx9FVa9qC2Uxj/5NhEYNsd3oswCEPxllJqOOYVZWFnlvXnTV9VG\r\n" + 
				"JQIDAQAB\r\n" + 
				"-----END PUBLIC KEY-----";
	    String publKeyPEM = temp_PublicKey.replace("-----BEGIN PUBLIC KEY-----", "");
	    publKeyPEM = publKeyPEM.replace("-----END PUBLIC KEY-----", "");
	    publKeyPEM = publKeyPEM.replace("\n", "");
	    publKeyPEM = publKeyPEM.replace("\r", "");
	    
	    String result;
		try {
		byte[] pkcs8EncodedBytes = Base64.getDecoder().decode(publKeyPEM);
    	X509EncodedKeySpec spec_PublicKey = new X509EncodedKeySpec(pkcs8EncodedBytes);
    	KeyFactory kf_PublicKey = KeyFactory.getInstance("RSA");
    	RSAPublicKey pubKey = (RSAPublicKey) kf_PublicKey.generatePublic(spec_PublicKey);
		//String JSONPayload = "{\"cardholderInfo\":{\"pan\":\"4036410123456789\",\"expirationDate\":{\"month\":\"06\",\"year\":\"2023\"}}";
        Payload payload = new Payload(JSONPayload);
        
        JWEHeader header = new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256CBC_HS512);
        RSAEncrypter rsaEncrypter = new RSAEncrypter(pubKey);
        System.out.println("rsaEncrypter : " + rsaEncrypter.getPublicKey());
        JWEObject issJwe = new JWEObject(header, payload);
        issJwe.encrypt(rsaEncrypter);
        String token = issJwe.serialize();
        System.out.println("token : " + token);
        result="{\r\n" + 
        		"\"status\":\"Y\",\r\n" + 
        		"\"CryptoData\":\""+token+"\"\r\n" + 
        		"}";
	    }
	    catch(Exception e) {
	    	result="{\r\n" + 
	    			"\"status\":\"N\",\r\n" + 
	    			"\"CryptoData\":\""+e+"\"\r\n" + 
	    			"}";
	    }
	    
        return result;
	}
/********************************DECRYPTION*************************************************/
	public String decrypt(String token) throws Exception {
		log.info("In JweSample.decrypt()*****************************");
		log.info("Encryptedtoken:: "+token);
		Security.addProvider(new BouncyCastleProvider());
		JWEObject visaJwe = JWEObject.parse(token);
		/*File f = new File("F:\\ICICI - CODE\\SampleCode\\key\\PrivateKey.key");
        FileInputStream fis = new FileInputStream(f);
	    DataInputStream dis = new DataInputStream(fis);
	    byte[] keyBytes = new byte[(int) f.length()];
	    dis.readFully(keyBytes);
        dis.close();*/

	    String temp = "-----BEGIN PRIVATE KEY-----\r\n" + 
	    		"MIIG/QIBADANBgkqhkiG9w0BAQEFAASCBucwggbjAgEAAoIBgQCi74eBoujkDUN8\r\n" + 
	    		"YOmjAChLYC8QqpZFttNk4BmIR8eGeq+iBpLHQF5QE7UODuGfXJb3wp9Xd6sc/rRk\r\n" + 
	    		"Jz4fFH+Q/I+9L3aU8Fpv1tkz4kuA9cDSAdkLrkikaa+nR0LwlWvuVe8J6KtcNUPg\r\n" + 
	    		"QQORxCinqPttGE4yBP7LmAti4X29uEdoLhUkuN5fBzGZkEDyslfeMbIUtUUg5KUH\r\n" + 
	    		"CsLzHN//tT5q754YaKBSJLRzLlzq6Ql5qS7Hok7FhJBKPZ0CnBrzLoqE+d0x/zmo\r\n" + 
	    		"5Pc8OTjNqL2oMf+i3xY6ucOzZv7KC07YA4Ior89qowu40OBTeN331K+uLBIkTI/z\r\n" + 
	    		"8+mQ2JQNJ0C4QNFgHiTpfUP3bWHCCZHlmjqreROSm4MWC6JRo/PZX0sxxGY1+b/Z\r\n" + 
	    		"jciunwnhm6Eg/rpqJxXSfj1NJpD77dKeFr//231xiITuoKGvn77N0Ehn+bjuaHtr\r\n" + 
	    		"DlZCx9USjTP/TsI3vuPnIStWXdnMeNw014A9wtK2Mz676K2F5aECAwEAAQKCAYAS\r\n" + 
	    		"M4HGqIUtnJGyXj0bOVRG/0qiqPu6c+7vcN1JTQNr8V6XUfapjXY7qcfq9xybKcOv\r\n" + 
	    		"j60vHy4dQhKysXOOE0Mg1iXUc23iu2rO3YhL9HaMxGcyzoQJewGgZDH8FMjUiUyS\r\n" + 
	    		"RkU6rSQfW8/mSDz21pvYBtd3W2S4z7gK1ERJWnkqbWCEscko3gHxSaNvzR6EPgn0\r\n" + 
	    		"x0Zma816HDCXNcuLTuly7jM3zOazQVTPeEw0JbS5hSjKz2xrXqVACUv5DyLv/LIU\r\n" + 
	    		"NgFauauUIGPECol6h/BwILlv6o0iblvvSeXFj6iQSLWlc1F3lXcvEv5SIitAc/Jk\r\n" + 
	    		"btzUdZaXWcX0bsDrML81UyoWMlKksAAww6Wgfivx0pT8xDmuYbmZhb7SwGfEhQWq\r\n" + 
	    		"wbLIvhoBwowPsCkG/WC1Yui17E5pSYZtPWZpBLjgjSbLCEOAcmV8g/uEypCpv4aN\r\n" + 
	    		"sed4JBnyTRJWVxcnfzrVsvu1Mr1YjwLKNB8x72A6r6wxu+ony8tx2OLtLfJrXOUC\r\n" + 
	    		"gcEA3o1ON7gA8UxAT8Fv+u6+jk51KylVGF6Yqn1cWWYQGh5iDoSMQTO3ijKmQgNq\r\n" + 
	    		"ifx8I1GCyLk7dwNmDVbmt+02Bdk76OFtg+dmQ0KlvXdY5CPVVdPXfDBqgHnHT9PN\r\n" + 
	    		"eCRdUh+qTcYdyqsc0X1/xu08qJKmZYBX5w8SGn4Smio3nl/HNerg9i1BF2DFo5pC\r\n" + 
	    		"NFBh9aA4+jryOH+xyWhHCFJ3VQ1EAI7yZToWdYLQa+vTIOJqdtioa1/jZP6Rubkd\r\n" + 
	    		"o03XAoHBALtse/Pp1eVLTEbo8F29fPAKL9k+nrABVZuAYROHPV3zgFiV+Oo271R9\r\n" + 
	    		"xnXpR/UVeh6ZuHEhd20tSJhvb4ePkAe2GpUaDeij0FnvSJXLN/gAAQ0yhwpg5NKD\r\n" + 
	    		"Wg59HqJuaYhI6TlItA4iIQM69KCOP/Xx7qOuEcAdcc5Q9HMGWoKD0mcezz4Q6uFK\r\n" + 
	    		"MH34XrORF37UKKyHEbzVFBBOn1hyjqC6P+zmZbgj9tab5LjpMN/VSSpJidGMichv\r\n" + 
	    		"SjjPYR9JRwKBwQCq7AGfn2zx5WsbFehH42Zsautn+7WEItrDTcZITq+dL6qFld0W\r\n" + 
	    		"En8q3117I56GXWiFw4tbV4/JBs4w/oXxyngMI9v0LnXqsSSEEcKy8d9OUAr/gNRl\r\n" + 
	    		"Z9XT2DNwJq4OUHdvpCwq0TZ+Oc7HQciJ4hgNK5wqJljcd2GjASKOTlArDUo1KbAe\r\n" + 
	    		"wYDVUJhZ3xZrkTS67ZP08qKnK8NCeRjc1mEZ7DdG6oJVpjgrhg1GZXbgMaQspJcs\r\n" + 
	    		"6Bb/sNgAuKB/lD8CgcBr7TWXqKDmcCzVbI/1uwc2Bve0xw2EVtBgQlYkc61P68eN\r\n" + 
	    		"u5bh8I5y/haJkbNBG4P+GREP/HCUKw5x0UHNM0uCVUgLcjxuKd7x2wvWTnbFVeNF\r\n" + 
	    		"IUKIJHHAE6mJTF2WtbQJqcq7lPUyak7OWGXECwYj75Q3JybLlWkSoKWTkyYNoDFJ\r\n" + 
	    		"9oDqwb0vzJQOBjcqejOoci2V5BW/wofSOCQkP5uITJhBKA+NMRCUVqMoJAhj7KM8\r\n" + 
	    		"OaqmQ6KYDBYWjrzj0kMCgcASaTntEDLDolNPXXSsICOe+Wr1hqubrRzPFjJxV+2I\r\n" + 
	    		"8jVeiHkPtsidn1zW72syercscaYOEMZYN614jJPBj5+FvT45FI23L4zdEDqIOeli\r\n" + 
	    		"eKTxDSLXXt9XLG5imnC4wU7zyjS+kjMJJJUwZfkNaSMHn70Iqs7sqIF9YbT0fE1d\r\n" + 
	    		"mdpSZlvMDXXIobym+WSBL/PVEw4GcaabzhNv/yVDtNB6ZgyT6QULJUoEm5TpcHM9\r\n" + 
	    		"pyMWlytdEZFmS34t12TyVso=\r\n" + 
	    		"-----END PRIVATE KEY-----";
	    String privKeyPEM = temp.replace("-----BEGIN PRIVATE KEY-----", "");
	    privKeyPEM = privKeyPEM.replace("-----END PRIVATE KEY-----", "");
	    privKeyPEM = privKeyPEM.replace("\n", "");
	    privKeyPEM = privKeyPEM.replace("\r", "");
		byte[] pkcs8EncodedBytes = Base64.getDecoder().decode(privKeyPEM);
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pkcs8EncodedBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey privKey = kf.generatePrivate(keySpec);
        visaJwe.decrypt(new RSADecrypter(privKey));
        return visaJwe.getPayload().toString();
	}
	public static void main (String args[])
	{
		try{
			//encrypt();
			//String result = decrypt("eyJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.IO3rL_24vPwEA_i1NnxnSMSQhGSH-WN4I0Gev_czPrsd_C9Ou0C5DLa5X10I_j100YEQ6i5shi3FG0f2eVw2AWmlQo8kG6Fd85LM0Rj-nFuTuSmcbIA-UP4yVzcQYKlXA418vKZRekrrHPoe2mfxLnoFqTAfimf24XnPtjkFYDz0CYpPUTzdm7Ri2nDWt6r__BsAlZc-JEeGLXksNuNMXhm1EM3F9UQlLh330VfsMyHXgQIK4jqtv0iTjN2LcCfptBTnha6xWm4YxaHC-ZqDcUrYYI0tvHmgz-i0ARI92EZ-v7I1Y5a634IHzvuYYq_YdALAxgy6Gx4wcuD_mF-i3PqXGi3MlY80bsC5S1GI0ul_gNTuyRlfAws4vXm2VI_uL1fFuBwuNzsxqparz1_JMTt-O95DhvwGIbjUqfJ4eoTfnXpfcCLZ4VmX74EKbVAjKzVUjj4z3rQWMgYm7L9W0dY8mkpEb1ibV7z-bDGVxWz2qUuaJs-GlN2hemHa9_d7.xDielPbMtgkdKD0rkPEN4A.kFqyHqycGbM4-dm5wdR6eOfQmOhYsDUktIrq-HuG7ZftRIWBnsc6f3KHgtEGyhvf4orU3nPCi3tPmvIC2DAWLUP8xH-hn-x6Etq0ARbcnMF50xoStgjkI06JZ3gX4vBc.NnR9vQAWOFNiwH-YjuVJn9tvo_QjK3YAIOxoUGs8KMM");
			String encr=new JweSample().encrypt("{\"cardholderInfo\":{\"NewPan\":\"4036418895001232\",\"NewExpDate\":\"2205\",\"Current PAN\":\"2205\",\"Expiration Date\":\"2304\"}}");
			System.out.println( "encr::"+encr);
			String decr=new JweSample().decrypt(encr);
			System.out.println( "decr::"+decr);
			
			
		}
		catch(Exception e){
			System.out.println(e.getMessage());
		}
	}

}
