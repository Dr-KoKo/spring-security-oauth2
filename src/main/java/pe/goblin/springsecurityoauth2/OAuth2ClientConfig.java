package pe.goblin.springsecurityoauth2;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class OAuth2ClientConfig {

	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
		httpSecurity
			.authorizeHttpRequests(AuthorizationManagerRequestMatcherRegistry -> AuthorizationManagerRequestMatcherRegistry
//				.requestMatchers("/loginPage").permitAll()
				.anyRequest().authenticated())
			.oauth2Login(Customizer.withDefaults());
//			.oauth2Login(OAuth2LoginConfigurer->OAuth2LoginConfigurer
//				.loginPage("/loginPage"));

		return httpSecurity.build();
	}
}
