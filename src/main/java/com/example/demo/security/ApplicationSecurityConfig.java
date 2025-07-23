package com.example.demo.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import static com.example.demo.security.ApplicationUserRole.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .authorizeRequests()
                .antMatchers("/", "index", "/css/*", "/js/*").permitAll()
                .antMatchers("/api/**").hasRole(STUDENT.name())
//                .antMatchers(HttpMethod.POST, "/management/api/v1/students/**").hasAuthority(COURSE_WRITE.getPermission())
//                .antMatchers(HttpMethod.PUT, "/management/api/v1/students/**").hasAuthority(COURSE_WRITE.getPermission())
//                .antMatchers(HttpMethod.DELETE, "/management/api/v1/students/**").hasAuthority(COURSE_WRITE.getPermission())
//                .antMatchers("/management/api/v1/students/**").hasAnyRole(ADMIN.name(), ADMIN_TRAINEE.name())
                .anyRequest()
                .authenticated()
                .and()
//                .httpBasic(); //basic authentication
                .formLogin()  //form base authentication
                .loginPage("/login").permitAll()
                .defaultSuccessUrl("/courses", true);
    }


    @Override
    @Bean
    protected UserDetailsService userDetailsService() {
        UserDetails annaSmith = User.builder()
                .username("annasmith")
                .password(passwordEncoder.encode("password"))
//                .roles(STUDENT.name()) // ROLE_STUDENT
                .authorities(STUDENT.grantedAuthorities())
                .build();

        UserDetails linda = User.builder()
                .username("linda")
                .password(passwordEncoder.encode("password123"))
//                .roles(ADMIN.name()) // ROLE_ADMIN
                .authorities(ADMIN.grantedAuthorities())
                .build();

        UserDetails tom = User.builder()
                .username("tom")
                .password(passwordEncoder.encode("password123"))
//                .roles(ADMIN_TRAINEE.name()) // ROLE_ADMIN_TRAINEE
                .authorities(ADMIN_TRAINEE.grantedAuthorities())
                .build();

        return new InMemoryUserDetailsManager(
                annaSmith,
                linda,
                tom
        );
    }
}
