using UnityEngine;
using UnityEngine.UI;
using System.Collections;
using System.Text;

namespace Rowbots.Prototypes{
	public class UI : MonoBehaviour {

		[SerializeField] InputField payloadInput;
		[SerializeField] InputField secret;
		[SerializeField] Button button;
		[SerializeField] Text text;

		void Start(){
			payloadInput.text = "jucas";
			secret.text = "jucas";
			DoStuff();
			button.onClick.AddListener(DoStuff);
		}

		void DoStuff(){
			if(!string.IsNullOrEmpty(payloadInput.text) && !string.IsNullOrEmpty(secret.text)){
				Person payload = new Person();				
				payload.name = payloadInput.text;												
				string jwt = Rowbots.Crypto.JWT.GenerateToken(payload, secret.text);				
				bool verified = Rowbots.Crypto.JWT.VerifyIntegrity(jwt, secret.text);				
				text.text = "JSON Web Token: " + jwt;
				text.text += "\nVerification Status: " + verified.ToString();
				string payloadContent = Rowbots.Crypto.JWT.GetPayloadContent(jwt, secret.text);			
				text.text += "\n Payload data after verification: " + payloadContent;							
			}
		}

		struct Person{
			public string name;
		}

	}
}