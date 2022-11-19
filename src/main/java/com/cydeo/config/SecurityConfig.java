package com.cydeo.config;

import com.cydeo.service.SecurityService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Configuration
public class SecurityConfig {

    private final SecurityService securityService;
    private final AuthSuccessHandler authSuccessHandler;

    public SecurityConfig(SecurityService securityService, AuthSuccessHandler authSuccessHandler) {
        this.securityService = securityService;
        this.authSuccessHandler = authSuccessHandler;
    }

//    @Bean
//    public UserDetailsService userDetailsService(PasswordEncoder encoder){
//        List<UserDetails> userList = new ArrayList<>();
//
//        userList.add(
//                new User("mike",encoder.encode("password"), Arrays.asList(new SimpleGrantedAuthority("ROLE_ADMIN")))
//        );
//
//        userList.add(
//                new User("ozzy",encoder.encode("password"), Arrays.asList(new SimpleGrantedAuthority("ROLE_MANAGER")))
//        );
//
//        return new InMemoryUserDetailsManager(userList);
//
//    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {    // Encoded Password and Gave Form

        return http
                .authorizeRequests()
//                .antMatchers("/user/**").hasRole("ADMIN")    //using hasRole automatically will add role_prefix.
                // Spring's hasAuthority method describes roles (Role description here must math the role in DB )
                .antMatchers("/user/**").hasAuthority("Admin") // There are 3 roles: Admin, Manager, Employee Admin should only see user related pages
                .antMatchers("/project/**").hasAuthority("Manager")  // Manager-> project related
                .antMatchers("/task/employee/**").hasAuthority("Employee")  // Employee-> employee task related
                .antMatchers("/task/**").hasAuthority("Manager")    // Manager-> tasks related
//                .antMatchers("/task/**").hasAnyRole("EMPLOYEE","ADMIN")   // hasAnyRole is for more roles
//                .antMatchers("/task/**").hasAuthority("ROLE_EMPLOYEE")
                .antMatchers(               // antMatchers are related to the pages For example: directory or controllers
                        "/",
                        "/login",
                        "/fragments/**",
                        "/assets/**",
                        "/images/**"
                ).permitAll()              // we don't Spring to put any security on this part above otherwise it will block
                .anyRequest().authenticated()
                .and()
//                .httpBasic()
                .formLogin()        // My login form introduced to Spring
                .loginPage("/login")  // That Login Controller gives the view of Login page
//                    .defaultSuccessUrl("/welcome")   // when user is authenticated it lands on this page
                .successHandler(authSuccessHandler)
                .failureUrl("/login?error=true")    // if user/pass is wrong we want to navigate here
                .permitAll()    // this form accessible by anyone
                .and()
                .logout()
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                .logoutSuccessUrl("/login")
                .and()
                .rememberMe()
                .tokenValiditySeconds(120)
                .key("cydeo")
                .userDetailsService(securityService)
                .and()
                .build();
    }

}
