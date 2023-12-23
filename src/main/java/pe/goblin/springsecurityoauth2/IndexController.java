package pe.goblin.springsecurityoauth2;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class IndexController {
	@Autowired
	private ClientRegistrationRepository clientRegistrationRepository;

	@GetMapping
	public String index() {
		ClientRegistration keycloakRegistration = clientRegistrationRepository.findByRegistrationId("keycloak");

		String clientId = keycloakRegistration.getClientId();
		String redirectUri = keycloakRegistration.getRedirectUri();

		System.out.println("clientId = " + clientId);
		System.out.println("redirectUri = " + redirectUri);
		return "index";
	}
}
