package com.yusuf.security.config;

import jakarta.servlet.Filter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {
    private final JwtAuthenticationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf()
                .disable() // CSRF korumasını devre dışı bırak
                .authorizeHttpRequests()
                .requestMatchers("/api/v1/auth/**") // Belirli URL'leri kısıtlamak için kullanılan bir ifade (Boş string tüm URL'leri temsil eder)
                .permitAll() // Belirtilen URL'leri herkesin erişebileceği şekilde konfigüre et
                .anyRequest()
                .authenticated() // Diğer tüm URL'ler için kimlik doğrulama gerektir
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS) // Oturum yönetimini STATELESS olarak ayarla (oturum kullanma)
                .and()
                .authenticationProvider(authenticationProvider) // Özel kimlik doğrulama sağlayıcısını belirt
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class); // JWT kimlik doğrulama filtresini, kullanıcı adı ve şifre tabanlı kimlik doğrulama filtresinden önce ekler

        return http.build();
    }
}
