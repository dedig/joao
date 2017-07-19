using UnityEngine;
using System.Collections;
using System.Security.Cryptography;
using System.Text;

namespace Rowbots.Crypto{
	// some bits based on Levitkon's answer on https://stackoverflow.com/questions/10055158/is-there-a-json-web-token-jwt-example-in-c
	public class JWT {

	const string headerJSON = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";

	static string ToBase64URL(string str){
		str = System.Convert.ToBase64String(Encoding.UTF8.GetBytes(str));
		return Base64Escape(str);
	}

	static string Base64Escape(string str){
		return str.Replace("=", string.Empty).Replace("/","_").Replace("+","-");
	}

	static string ToHMAC(string str, string secret){
		byte[] computedHash;
		using (HMACSHA256 hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret))){
			computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(str));
		};
		return Base64Escape(System.Convert.ToBase64String(computedHash));
	}

	public static string GenerateToken(object payload, string secret){		
		return GenerateTokenFromString(JsonUtility.ToJson(payload), secret);
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