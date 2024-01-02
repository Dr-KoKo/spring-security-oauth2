package pe.goblin.springsecurityoauth2.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.oauth2.client.OAuth2AuthorizationSuccessHandler;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoginController {
	@Autowired
	private DefaultOAuth2AuthorizedClientManager oAuth2AuthorizedClientManager;
	@Autowired
	private OAuth2AuthorizedClientRepository oAuth2AuthorizedClientRepository;
	private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder.getContextHolderStrategy();

	@GetMapping("/oauth2Login")
	public String oauth2Login(HttpServletRequest request, HttpServletResponse response, Model model) {
		Authentication authentication = securityContextHolderStrategy.getContext().getAuthentication();

		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
			.withClientRegistrationId("keycloak")
			.principal(authentication)
			.attribute(HttpServletRequest.class.getName(), request)
			.attribute(HttpServletResponse.class.getName(), response)
			.build();

		OAuth2AuthorizationSuccessHandler successHandler = (authorizedClient, principal, attributes) -> {
			oAuth2AuthorizedClientRepository
				.saveAuthorizedClient(authorizedClient, principal,
					(HttpServletRequest) attributes.get(HttpServletRequest.class.getName()),
					(HttpServletResponse) attributes.get(HttpServletResponse.class.getName()));
			System.out.println("authorizedClient = " + authorizedClient);
			System.out.println("principal = " + principal);
			System.out.println("attributes = " + attributes);
		};
		oAuth2AuthorizedClientManager.setAuthorizationSuccessHandler(successHandler);

		OAuth2AuthorizedClient authorizedClient = oAuth2AuthorizedClientManager.authorize(authorizeRequest);
		if (authorizedClient != null) {
			model.addAttribute("authorizedClient", authorizedClient.getAccessToken().getTokenValue());
		}

		return "home";
	}

	@GetMapping("/logout")
	public String logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
		SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
		logoutHandler.logout(request, response, authentication);
		return "redirect:/";
	}
}
