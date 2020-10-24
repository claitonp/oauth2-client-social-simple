/*
 * Copyright 2012-2015 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.example;

import static org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;

import lombok.extern.slf4j.Slf4j;
import reactor.netty.http.client.HttpClient;
import reactor.netty.tcp.ProxyProvider;

@Slf4j
@RestController
@SpringBootApplication
public class SocialApplication extends WebSecurityConfigurerAdapter {
   
	public static void main(String[] args) {
		SpringApplication.run(SocialApplication.class, args);
	}
		
    @GetMapping("/user")
    public Map<String, String> user(@AuthenticationPrincipal OAuth2User principal) {
        String name = principal.getAttribute("name");
        String email = principal.getAttribute("email");
        Map<String, String> result = new HashMap<String, String>();
        
        result.put("name", name);
        result.put("email", email);
        log.info("user: {}", principal);
        return result;
    }
    
    @Override
    protected void configure(HttpSecurity http) throws Exception {

        SimpleUrlAuthenticationFailureHandler handler = new SimpleUrlAuthenticationFailureHandler("/");
        
        http.authorizeRequests(a -> a.antMatchers("/", "/error", "/webjars/**").permitAll().anyRequest().authenticated())
            .logout(l -> l.logoutSuccessUrl("/").permitAll() )
            .exceptionHandling(e -> e.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)))
            .csrf(c -> c.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
//            .oauth2Login();
            .oauth2Login(o -> o.failureHandler((request, response, exception) -> {
                        request.getSession().setAttribute("error.message", exception.getMessage());
                        handler.onAuthenticationFailure(request, response, exception);
                    }
            ));
    }
    
    @GetMapping("/error")
    @ResponseBody
    public String error(HttpServletRequest request) {
        String message = (String) request.getSession().getAttribute("error.message");
        request.getSession().removeAttribute("error.message");
        return message;
    }
    
    @Bean
    public WebClient rest(ClientRegistrationRepository clients, OAuth2AuthorizedClientRepository authz) {
        ServletOAuth2AuthorizedClientExchangeFilterFunction oauth2 = new ServletOAuth2AuthorizedClientExchangeFilterFunction(clients, authz);
        
        HttpClient httpClient = HttpClient.create()
                                          .tcpConfiguration(tcpClient -> tcpClient.proxy(proxy -> proxy.type(ProxyProvider.Proxy.HTTP)
                                                                                                       .host("proxycor")
                                                                                                       .port(8080)
                                                                                                       .username("80130143")
//                                                                                                      .password(p -> p.sp.getBytes())
                                                                                                       ));
        ReactorClientHttpConnector connector = new ReactorClientHttpConnector(httpClient);
    
    
//        WebClient result = WebClient.builder().filter(oauth2).build();
        WebClient result = WebClient.builder().clientConnector(connector).filter(oauth2).build();
    
        return result;
    }

    @Bean
    public OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService(WebClient rest) {
        DefaultOAuth2UserService delegate = new DefaultOAuth2UserService();
        return request -> {
            OAuth2User user = delegate.loadUser(request);
            if (!"github".equals(request.getClientRegistration().getRegistrationId())) {
                return user;
            }

            OAuth2AuthorizedClient client = new OAuth2AuthorizedClient(request.getClientRegistration(), user.getName(), request.getAccessToken());
            String url = user.getAttribute("organizations_url");
            List<Map<String, Object>> orgs = rest
                    .get().uri(url)
                    .attributes(oauth2AuthorizedClient(client))
                    .retrieve()
                    .bodyToMono(List.class)
                    .block(); //timeout

            if (orgs.stream().anyMatch(org -> "spring-projects".equals(org.get("login")))) {
                return user;
            }

            throw new OAuth2AuthenticationException(new OAuth2Error("invalid_token", "Not in Spring Team", ""));
        };
    }

}
