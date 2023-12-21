package pe.goblin.springsecurityoauth2;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
		httpSecurity
			.httpBasic(httpBasicConfigurer -> httpBasicConfigurer
				.authenticationEntryPoint(new CustomAuthenticationEntryPoint()));

		httpSecurity
			.authorizeHttpRequests(authorizationManagerRequestMatcherRegistry -> authorizationManagerRequestMatcherRegistry
				.anyRequest().authenticated());

		httpSecurity
			.sessionManagement(sessionManagementConfigurer -> sessionManagementConfigurer
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

		return httpSecurity.build();
	}
}
