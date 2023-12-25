package pe.goblin.springsecurityoauth2;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

@RestController
public class IndexController {
	@Autowired
	private ClientRegistrationRepository clientRegistrationRepository;

	@GetMapping("/")
	public String index() {
		return "index";
	}

	@GetMapping("/user")
	public OAuth2User user(String accessToken) {
		ClientRegistration keycloakClientRegistration = clientRegistrationRepository.findByRegistrationId("keycloak");

		OAuth2AccessToken oAuth2AccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, accessToken, Instant.now(), Instant.MAX);

		OAuth2UserRequest oAuth2UserRequest = new OAuth2UserRequest(keycloakClientRegistration, oAuth2AccessToken);

		DefaultOAuth2UserService userService = new DefaultOAuth2UserService();
		OAuth2User oAuth2User = userService.loadUser(oAuth2UserRequest);

		return oAuth2User;
	}

	@GetMapping("/oidc")
	public OAuth2User user(String accessToken, String idToken) {
		ClientRegistration keycloakClientRegistration = clientRegistrationRepository.findByRegistrationId("keycloak");

		OAuth2AccessToken oAuth2AccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, accessToken, Instant.now(), Instant.MAX, Set.of("openid"));

		Map<String, Object> idTokenClaims = new HashMap<>();
		idTokenClaims.put(IdTokenClaimNames.ISS, "http://localhost:8080/realms/oauth2");
		idTokenClaims.put(IdTokenClaimNames.SUB, "OIDC0");
		idTokenClaims.put("preferred_username", "user");

		OidcIdToken oidcIdToken = new OidcIdToken(idToken, Instant.now(), Instant.MAX, idTokenClaims);


		OidcUserRequest oidcUserRequest = new OidcUserRequest(keycloakClientRegistration, oAuth2AccessToken, oidcIdToken);

		OidcUserService userService = new OidcUserService();
		OidcUser oidcUser = userService.loadUser(oidcUserRequest);

		return oidcUser;
	}
}
