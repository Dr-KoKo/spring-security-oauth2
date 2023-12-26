package pe.goblin.springsecurityoauth2;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
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
				.requestMatchers("/home").permitAll()
				.anyRequest().authenticated());

		httpSecurity
			.oauth2Login(Customizer.withDefaults());

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
		logoutSuccessHandler.setPostLogoutRedirectUri("http://localhost:8081/home");
		return logoutSuccessHandler;
	}
}
