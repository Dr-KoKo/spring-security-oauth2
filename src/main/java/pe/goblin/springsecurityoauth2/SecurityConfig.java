package pe.goblin.springsecurityoauth2;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {
	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
		httpSecurity
			.authorizeHttpRequests(customizer -> customizer
				.anyRequest().authenticated())
			.formLogin(Customizer.withDefaults())
			.apply(new CustomSecurityConfigurer().setSecure(false));

		return httpSecurity.build();
	}
}
