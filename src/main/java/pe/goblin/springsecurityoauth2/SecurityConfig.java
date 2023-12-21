package pe.goblin.springsecurityoauth2;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;

import java.io.IOException;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
		httpSecurity
			.formLogin(Customizer.withDefaults())
			.httpBasic(Customizer.withDefaults());

		httpSecurity
			.authorizeHttpRequests(customizer -> customizer
				.anyRequest().authenticated());

//		httpSecurity
//			.exceptionHandling(customizer->customizer
//				.authenticationEntryPoint(new AuthenticationEntryPoint() {
//					@Override
//					public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
//						System.out.println("custom entryPoint");
//					}
//				}));

		return httpSecurity.build();
	}
}
