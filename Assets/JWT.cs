using UnityEngine;
using System.Collections;
using System.Security.Cryptography;
using System.Text;

namespace Rowbots.Crypto{
	public class JWT {

		const string headerJSON = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";

	static string ToBase64URL(string str){
		str = System.Convert.ToBase64String(Encoding.UTF8.GetBytes(str));
		str = str.Split('=')[0]; // Remove any trailing '='s
		return str;
	}

	static string ToHMAC(string str, string secret){	
		byte[] arrayToComputeFromString = Encoding.UTF8.GetBytes(str);			
		HMACSHA256 hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
		byte[] computedHash = hmac.ComputeHash(arrayToComputeFromString);
		return System.Convert.ToBase64String(computedHash).Replace("=",string.Empty).Replace("/","_").Replace("+","_"); //These Replaces are for conformity with JWT spec
	}

	public static string GenerateToken(object payload, string secret){		
		string header = ToBase64URL(headerJSON);				
		string payloadJson = ToBase64URL(JsonUtility.ToJson(payload));
		string headerload = header + "." + payloadJson;
		string signature = ToHMAC(str: headerload, secret: secret);
		return headerload + "." + signature;
	}

	public static string GenerateTokenFromString(string payload, string secret){		
		string header = ToBase64URL(headerJSON);				
		string payloadJson = ToBase64URL(payload);
		string headerload = header + "." + payloadJson;
		string signature = ToHMAC(str: headerload, secret: secret);
		return headerload + "." + signature;
	}

	public static bool VerifyIntegrity(string jwt, string secret){
		string[] splitToken = jwt.Split('.');
		if(splitToken.Length!=3){
			Debug.Log("[JWT] Invalid string");
			return false;
		}
		string headerload = ToHMAC((splitToken[0] + '.' + splitToken[1]), secret);
		return headerload.Equals(splitToken[2]);
	}

	public static string GetPayloadContent(string jwt, string secret){
		if(!VerifyIntegrity(jwt, secret)){
			Debug.LogWarning("[JWT] String integrity cannot be verified");
			return string.Empty;
		}
		string[] split = jwt.Split('.');
		if(split.Length!=3){
			Debug.LogWarning("[JWT] String somehow got past verification but doesn't conform to JWT standards");
			return string.Empty;
		}
		int len = split[1].Length % 4;
		if (len > 0){
			split[1] = split[1].PadRight(split[1].Length + (4 - len), '=');
		} 		
		string convertedString = Encoding.UTF8.GetString(System.Convert.FromBase64String(split[1]));		
		return convertedString;
	}

	}
}