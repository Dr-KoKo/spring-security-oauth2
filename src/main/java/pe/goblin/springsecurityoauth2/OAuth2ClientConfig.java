package pe.goblin.springsecurityoauth2;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

@Configuration
@EnableWebSecurity
public class OAuth2ClientConfig {
	@Autowired
	private ClientRegistrationRepository clientRegistrationRepository;

	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
		httpSecurity
			.authorizeHttpRequests(authorizationManagerRequestMatcherRegistry -> authorizationManagerRequestMatcherRegistry
				.requestMatchers("/login").permitAll()
				.anyRequest().permitAll());

		httpSecurity
			.oauth2Login(oAuth2LoginConfigurer->oAuth2LoginConfigurer
				.loginPage("/login")
				.authorizationEndpoint(authorizationEndpointConfig -> authorizationEndpointConfig
					.baseUri("/oauth2/v1/authorization"))
				.redirectionEndpoint(redirectionEndpointConfig -> redirectionEndpointConfig
					.baseUri("/login/v1/oauth2/code/*")));
//				.loginProcessingUrl("/login/v1/oauth2/code/*"));

		httpSecurity
			.logout(logoutConfigurer->logoutConfigurer
				.logoutSuccessHandler(oidcLogoutSuccessHandler())
				.clearAuthentication(true)
				.invalidateHttpSession(true)
				.deleteCookies("JSESSIONID"));

		return httpSecurity.build();
	}

	private LogoutSuccessHandler oidcLogoutSuccessHandler() {
		OidcClientInitiatedLogoutSuccessHandler logoutSuccessHandler = new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);
		logoutSuccessHandler.setPostLogoutRedirectUri("http://localhost:8081/login");
		return logoutSuccessHandler;
	}
}
