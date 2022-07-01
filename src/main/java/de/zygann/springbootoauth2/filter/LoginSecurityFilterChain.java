package de.zygann.springbootoauth2.filter;

import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;

@EnableWebSecurity
public class LoginSecurityFilterChain
{

    public SecurityFilterChain loginSecurityFilterChain(HttpSecurity http) throws Exception
    {
        // antMatcher allows page request to /, /error and /webjars/**
        // otherwise a unauthorized error returns
        // because of anyRequest().authenticated() methods
        http.authorizeRequests(
                        authorizeRequests -> authorizeRequests.antMatchers("/", "/error", "/webjars/**").permitAll()
                                .anyRequest().authenticated())
                // default would be a redirect to login page -> the authenticationEntryPoint responds with a 401
                .exceptionHandling(e -> e.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)))
                .oauth2Login();
        return http.build();

    }
}
