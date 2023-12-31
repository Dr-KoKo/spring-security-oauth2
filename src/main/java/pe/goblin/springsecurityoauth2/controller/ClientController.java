package pe.goblin.springsecurityoauth2.controller;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.Arrays;

@Controller
public class ClientController {
	@Autowired
	private OAuth2AuthorizedClientRepository authorizedClientRepository;
	@Autowired
	private OAuth2AuthorizedClientService authorizedClientService;
	private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder.getContextHolderStrategy();

	@GetMapping("/client")
	public String client(HttpServletRequest request, Model model) {
		String registrationId = "keycloak1";
		SecurityContext context = securityContextHolderStrategy.getContext();
		Authentication authentication = context.getAuthentication();

		OAuth2AuthorizedClient authorizedClient1 = authorizedClientRepository.loadAuthorizedClient(registrationId, authentication, request);
		OAuth2AuthorizedClient authorizedClient2 = authorizedClientService.loadAuthorizedClient(registrationId, authentication.getName());

		OAuth2AccessToken accessToken = authorizedClient1.getAccessToken();

		DefaultOAuth2UserService oAuth2UserService = new DefaultOAuth2UserService();
		OAuth2User oAuth2User = oAuth2UserService.loadUser(
			new OAuth2UserRequest(authorizedClient1.getClientRegistration(), accessToken));

		OAuth2AuthenticationToken authResult = new OAuth2AuthenticationToken(
			oAuth2User, Arrays.asList(new SimpleGrantedAuthority("ROLE_USER")), authorizedClient1.getClientRegistration().getRegistrationId());

		SecurityContext emptyContext = this.securityContextHolderStrategy.createEmptyContext();
		emptyContext.setAuthentication(authResult);
		this.securityContextHolderStrategy.setContext(emptyContext);

		model.addAttribute("accessToken", accessToken.getTokenValue());
		model.addAttribute("refreshToken", authorizedClient1.getRefreshToken().getTokenValue());
		model.addAttribute("principalName", oAuth2User.getName());
		model.addAttribute("clientName", authorizedClient1.getClientRegistration().getClientName());

		return "client";
	}
}
