package pe.goblin.springsecurityoauth2;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class IndexController {
	@GetMapping("/")
	public String index() {
		return "index";
	}

	@GetMapping("/user")
	public OAuth2User user() {
		OAuth2AuthenticationToken authenticationFromSecurityContext = (OAuth2AuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
		OAuth2User principal = authenticationFromSecurityContext.getPrincipal();

		System.out.println("principal = " + principal);

		return principal;
	}

	@GetMapping("/oauth2User")
	public OAuth2User user(@AuthenticationPrincipal OAuth2User oAuth2User) {
		System.out.println("oAuth2User = " + oAuth2User);
		return oAuth2User;
	}

	@GetMapping("/oidcUser")
	public OAuth2User user(@AuthenticationPrincipal OidcUser oidcUser) {
		System.out.println("oidcUser = " + oidcUser);
		return oidcUser;
	}
}
