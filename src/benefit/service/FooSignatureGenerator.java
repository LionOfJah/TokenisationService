package benefit.service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import benefit.util.PayloadUtility;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.logging.Logger;

/**
 * @author Aravind Bukya (FEB 11, 2021)
 */

public class FooSignatureGenerator {
private static final Logger log=Logger.getLogger(FooSignatureGenerator.class.getName());
public static final String SIGNING_ALGORITHM = "HmacSHA256";
public static final String SIGNING_KEY_FOR_VALIDATE_CRYPTO = "7CvHYSKCu8CaVtANs6xXh3Mwx7HkV96KEtJEUbLrLgQPRZeERMHQyuUtnenmfLpQ"; // ICICI
//public static final String REQUEST_BODY_FOR_VALIDATE_CRYPTO = "{\"tokenRequestorID\":\"40010080278\",\"tokenReferenceID\":\"DNITHE302103135943058773\",\"accountIdHash\":\"CE62283F46849994E08CADB975A95565C14F86FEE9792907B13A7D7332402988\",\"panReferenceID\":\"V-3020337392152504264142\",\"encryptedData\":\"eyJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.IA_tdl22JLmmday6bt8cKegVk6icTJora3fz2O1aVnuogfjEJw0Y_YKzOclkopsiAxZ8dtg042fCIH_lPgk3fpGOFbxmHzK9VeFaLnGIFDhV2DR6eo_K_84qVIReRYpMDRHEVvKvoj5f2xw1v28EQt-oT5c7cO2BVnP7XdeJaTm8tuDXQdZeOAyRJXbnHGnX4iosSkM_eb5OGnpraWuI__yhVMTDVqsV83c5LLG3lb13fmdTAmbpCsU3d4LUOq-Lz2TRvOTeGZgV5ER_Nh_HPAgOUp4BlUGSJoaWc1QulNr5upc2bBSry92RsQvZKlY6XlxO-bQ-200wtv36JSZVoIE23bVNIQvNkuY9GhCRhfVJqEgXY6YkmZ7bJWCMFj79uZtW5IzHJ4zqbv1IQqv_ewPF9xAOFsHTmcN-RZViDWDtsO_7FiFRqn_duAINfhBbkrIt6Ed7r7F0nfcamhi_Tk1iqLOQe7hYEwKp61Y9TcmEzTXedC_NvAq7FJPJBbfH.U4SNi2KE3K44CS9cXBEW7w.llkJxuzvSVAnjbprYgqAHj482P1MQt1VOZALXkE2wmVEB1XjDjTQNE4bPBxLMhp3fCzmchmQyZwDImu28vF61X0XFLd8zTAGr2TcEEBTNf0Ye0z8CrouQNP_nUwMZtgl3PbnJB35-k-LjfA_5EPlDl04uojtIyUVp9GttQ1Dtkc3wfTdiPAt8LnhrfldyYUyujgKT_qK3NZxoFIXdJt0QzEGah4Iv4GnhG8BKStez30nqrujcxtyQ4JahD2yaLIEigvQDlIt_qxlZ86JCqAtrjulkXRb7b427mRDnLlC3Taubugjmm0EmUZw_b3d7ja-fVPgL531Kct20pBDrxgRq9IVxw5jvIiKmv2aEfsydAzs3teXpKSfcpctTh9Gy8LPkJY24ga_tv92QMPnVS-6M4N26iYdxhZalzmu2UGQ2rU.S1tFO4TytpWvFPBA-52e6EljXglwrrX9aTExP4eb-6I\",\"deviceInfo\":{\"deviceID\":\"89dd7f044e6bfb9d9c7943f5\",\"deviceLanguageCode\":\"eng\",\"osType\":\"ANDROID\",\"osVersion\":\"9\",\"osBuildID\":\"PPR1.180610.011\",\"deviceType\":\"MOBILEPHONE_OR_TABLET\",\"deviceIDType\":\"Derived\",\"deviceManufacturer\":\"samsung\",\"deviceBrand\":\"samsung\",\"deviceModel\":\"SM-N950F\",\"deviceName\":\"R2FsYXh5IE5vdGU4\",\"tokenProtectionMethod\":\"SOFTWARE\"},\"tokenInfo\":{\"tokenType\":\"HCE\"},\"tspIdentifier\":\"VTS\",\"panSource\":\"KEY_ENTERED\",\"cvv2ResultsCode\":\"M\",\"clientWalletAccountID\":\"27bf68955fab5c48f508fe5d\",\"correlationID\":\"301042359420586\"}";
public static final Charset CHARSET = StandardCharsets.UTF_8;
private String flag=null;

		public String generateSignatureAsBase64ValidateCrypto(String REQUEST_BODY_FOR_VALIDATE_CRYPTO, String PreGeneratedSignature) throws InvalidKeyException,NoSuchAlgorithmException {
			log.info("PreGeneratedSignature: "+PreGeneratedSignature+"\n"+"REQUEST_BODY_FOR_VALIDATE_CRYPTO:: "+REQUEST_BODY_FOR_VALIDATE_CRYPTO);
			Mac sig = Mac.getInstance(SIGNING_ALGORITHM);
	        SecretKeySpec secretKey = new SecretKeySpec(SIGNING_KEY_FOR_VALIDATE_CRYPTO.getBytes(), SIGNING_ALGORITHM);
	        sig.init(secretKey);
	        byte[] payloadSignature = sig.doFinal(REQUEST_BODY_FOR_VALIDATE_CRYPTO.getBytes(StandardCharsets.UTF_8));
	        String signature = Base64.getEncoder().encodeToString(payloadSignature);
	        System.out.println("Validate Crypto: "+signature);
	        if(PreGeneratedSignature.equals(signature)){
	        	flag="Y";
	        }
	        else {
	        	flag="N";
	        }
	        log.info("flag::"+flag);
	        return flag;  
	    }
		
		public String generateSignatureAsBase64(String cryptoData,String JSONPayload) throws Exception { 
			String base64Signature = null;
			System.out.println("JSONPayload::"+JSONPayload.toString()+"\n"+"cryptoData::"+cryptoData);
			String requestBody =new PayloadUtility().getPayload(cryptoData,JSONPayload);
			try {
				Mac sig = Mac.getInstance("HmacSHA256"); 
		        SecretKeySpec secretKey = new SecretKeySpec(SIGNING_KEY_FOR_VALIDATE_CRYPTO.getBytes(), "HmacSHA256");         
		        sig.init(secretKey); 
		        byte[] payloadSignature = sig.doFinal(requestBody.getBytes(StandardCharsets.UTF_8));
		        String signdata=Base64.getEncoder().encodeToString(payloadSignature); 
		       // base64Signature ="{\"Signature\":\""+signdata+"\"}";
		       String  encodedData=Base64.getEncoder().encodeToString(requestBody.getBytes());
		        base64Signature="{\"Signature\":\""+signdata+"\",\"data\":\""+encodedData+"\"}";
		        		
		        
		        System.out.println(base64Signature); 
		        boolean status="Uisvaf+lO6r/gSGEGjkE4v0qA4UEdTMT+MM/BqYGa0s=".equals(base64Signature);
		        System.out.println("status::"+status);
			}
			catch(Exception E) {
				base64Signature="{\r\n" + 
						"\"status\":\"fail\"\r\n" + 
						"\"message\":\""+E+"\"\r\n" + 
						"}";
			}
	        return base64Signature;      
	    } 
		public String generateSignature(String REQUEST_BODY_FOR_VALIDATE_CRYPTO) throws NoSuchAlgorithmException, InvalidKeyException {
			log.info("REQUEST_BODY_FOR_VALIDATE_CRYPTO:: "+REQUEST_BODY_FOR_VALIDATE_CRYPTO);
			Mac sig = Mac.getInstance(SIGNING_ALGORITHM);
	        SecretKeySpec secretKey = new SecretKeySpec(SIGNING_KEY_FOR_VALIDATE_CRYPTO.getBytes(), SIGNING_ALGORITHM);
	        sig.init(secretKey);
	        byte[] payloadSignature = sig.doFinal(REQUEST_BODY_FOR_VALIDATE_CRYPTO.getBytes(StandardCharsets.UTF_8));
	        String signature = Base64.getEncoder().encodeToString(payloadSignature);
	        System.out.println("Validate Crypto: "+signature);
	        log.info("flag::"+flag);
	        return signature;  	
		}
		
		public static void main(String[] args){
			//String REQUEST_BODY_FOR_VALIDATE_CRYPTOTest = "{\"tokenRequestorID\":\"40010080278\",\"tokenReferenceID\":\"DNITHE302101227705124163\",\"accountIdHash\":\"CE62283F46849994E08CADB975A95565C14F86FEE9792907B13A7D7332402988\",\"panReferenceID\":\"V-3020337392152504264142\",\"encryptedData\":\"eyJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.AFcGW5L4q7nxezGPoouCGYlUL25KHZQ3k2SxPYq6eNGJIrEWnVcXlCQ-z0vk8e3ohbMlYX1pt30hf3l_bOETag4UqlWhdoSyU5F91bJ0o4QEQtP__AVRoUhJoDAN_HhkIMXOs47cA3TLA0SDAoMG3pbXL0Cd8viR1VCJTmSXpa77qFVdFtxrm2JLkY9Tw8wpnQxGhijvLA-h-nZPja6cGUf65MdqkCtqcbkwfngMREvWLFfl16MbmsxEFOuaiFQ4YbUTLDo7iyClT4wFWwn6uzQnVs2qaZ8vEPJUmQexwmQ-8_cJMxLe_3AQ2Doh56tpp3vKb0mTIDnCBRQg6qfrdF0whnWuJe5qPRb-2iNP_hnpojzVySsQDurLIM-2D_iGu2cb1DQZrCsSKM0fEqAW3Y94YkSj6uiQ-xL7BRSYTfnvV4JcgXRKIMgw8e1pC3dIhAe77PbM4_ldoM3UwZH5Vj7iaukEtluO-uMHUu0kDDh-jAg8pE2PrXZsfwAHDfvI.pRDBjH0F3J-PvzDK.1FjUtNdBPWy62sctG7QFp2zqKijJ_BjMDDkUX9Jfw5PpB8QNTd646Vv-Zzs5CEue-3A0NeaRsx8ktfggXQqQswi6O55GZUV09LNa8murCTGqEDmwEgCtBAkbL7utd2HUQ8LVQkWeLNpx0gyYeBGamuqjKBqCYyelXyniIqeD-HrzAtQ-i-KuSV7HrYFn9-dYIrX6TlNqiEwZIvqm1uSfdeyX2pGZzANBZdJhQQyCLOem2KDSYCPDFWR7V1RoJ3ASCiaDrLLTGvOkToOtS8HvEXFBi8xhKtqq7MUo_Gp23_NdkJ4mX2go_URzybEEVLOlPsth1MJK7Eeo_65KRn5I5WPfiPDaUeZxb5qbjAfxMRgvDB_htFCxzY1azSfcDwQ3DXvFs-AyI3uhwtbrkVabKLrExFRjWp_85wqp.TszD_Rw--UcyR4UPhUbp-Q\",\"deviceInfo\":{\"deviceID\":\"89dd7f044e6bfb9d9c7943f5\",\"deviceLanguageCode\":\"eng\",\"osType\":\"ANDROID\",\"osVersion\":\"9\",\"osBuildID\":\"PPR1.180610.011\",\"deviceType\":\"MOBILEPHONE_OR_TABLET\",\"deviceIDType\":\"Derived\",\"deviceManufacturer\":\"samsung\",\"deviceBrand\":\"samsung\",\"deviceModel\":\"SM-N950F\",\"deviceName\":\"R2FsYXh5IE5vdGU4\",\"tokenProtectionMethod\":\"SOFTWARE\"},\"tokenInfo\":{\"tokenType\":\"HCE\"},\"tspIdentifier\":\"VTS\",\"panSource\":\"KEY_ENTERED\",\"cvv2ResultsCode\":\"M\",\"clientWalletAccountID\":\"27bf68955fab5c48f508fe5d\",\"correlationID\":\"301012277051240\"}";
				String REQUEST_BODY_FOR_VALIDATE_CRYPTOTest="{\"tokenRequestorID\":\"40010080278\",\"tokenReferenceID\":\"DNITHE302106333299592016\",\"panReferenceID\":\"V-3020337392152504264142\",\"encryptedData\":\"eyJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.CX6-EeIfDbG_7P2rgP-mAtvvFZ05SobdBqI5VYKd6uaUSzr6YSDekCcQ_1WKEKBA1SZP6rgsQ8oHvqOorxTj-NIIyr07sKKfQhtmIUREqVXvTAeURxb9LeZSKV4mZbwpnEGK0a6iZ9okXJ39Qi5tvaGfhvURixZ226Wse0PbbRSdedglJ_7xNNuBhAX3V54j_dDCgh7imUGcj8LKBk2JhBD75RRlvMFrwxS7rc0qAxPBUI2RAdlDmnhoy2BCN-N0yBbCtss0KT5f7IM3qOP2P-m5ZldjSY3FANzN0rpL_DrU2JWtQK8GQgLJKBpd5umdXApFUopmvUDmrgHLSBbgxYdILF_MOa-xQUqzR9E4X2YZxc7YBpH3isEu8jDQae8s__DEJvIEBZA0AwLAFgXmTmTQ2Y0XoDXyNO1w1VHbPNXxgbqZAuNyRtHea6-nTqpKEh5uzUCkLvFI5IjZuO_OTc38aBaAx2p2MZbWVcLZyubVo2kkHFVOjXERcJ15y4r_.j6dyEayagJjneXXM.gCzf99zRmdnIO6fvM43Zz7FlcqXPZ0Xf_OtVaBklXz3yQjuHz28D-YE6rdFd7n5H3Qse1EIrfjPqgRZHxxsIaWgB.2qipo7l-S4HAAuyDLZnHiQ\",\"deviceInfo\":{\"deviceID\":\"89dd7f044e6bfb9d9c7943f5\",\"deviceType\":\"MOBILEPHONE_OR_TABLET\"},\"tspIdentifier\":\"VTS\",\"otpReason\":\"PROVISIONING\",\"otpMaxReached\":\"false\",\"clientWalletAccountID\":\"27bf68955fab5c48f508fe5d\",\"correlationID\":\"301063332995919\"}";	
			try{
				//new FooSignatureGenerator().generateSignatureAsBase64ValidateCrypto(REQUEST_BODY_FOR_VALIDATE_CRYPTOTest,"gbKkxHIK0Z/taWaiN3kTrv8G5Oz7X5853Vtr76T2ceE=");
				new FooSignatureGenerator().generateSignatureAsBase64("gbKkxHIK0Z/taWaiN3kTrv8G5Oz7X5853Vtr76T2ceE=",REQUEST_BODY_FOR_VALIDATE_CRYPTOTest);
				
			}catch(Exception e)
				{
			}
		}
	}