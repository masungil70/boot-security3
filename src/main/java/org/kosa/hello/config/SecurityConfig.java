package org.kosa.hello.config;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

import org.kosa.hello.auth.filter.JsonUsernamePasswordAuthenticationFilter;
import org.kosa.hello.member.AuthFailureHandler;
import org.kosa.hello.member.AuthSucessHandler;
import org.kosa.hello.member.MemberService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import jakarta.servlet.DispatcherType;


@Configuration
@EnableWebSecurity // 시큐리티 필터 등록
public class SecurityConfig {
	
	@Autowired
	private MemberService memberService;
	@Autowired
	private AuthSucessHandler authSucessHandler;
	@Autowired
	private AuthFailureHandler authFailureHandler;
	
	// BCryptPasswordEncoder는 Spring Security에서 제공하는 비밀번호 암호화 객체 (BCrypt라는 해시 함수를 이용하여 패스워드를 암호화 한다.)
	// 회원 비밀번호 등록시 해당 메서드를 이용하여 암호화해야 로그인 처리시 동일한 해시로 비교한다.
	// 의존성 주입을 위한 함수를 Bean 객체로 리턴할 수 있게 함수를 구현한다 
	@Bean
	public BCryptPasswordEncoder encryptPassword() {
		return new BCryptPasswordEncoder();
	}
	
	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception { 
		/*
		 csrf 토큰 활성화시 사용
		 쿠키를 생성할 때 HttpOnly 태그를 사용하면 클라이언트 스크립트가 보호된 쿠키에 액세스하는 위험을 줄일 수 있으므로 쿠키의 보안을 강화할 수 있다.
		*/
		//http.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
        http.csrf(AbstractHttpConfigurer::disable)	// csrf비활성화  
    	.authorizeHttpRequests(authorize -> authorize 
        	.dispatcherTypeMatchers(DispatcherType.FORWARD, DispatcherType.ERROR)
			.permitAll() // 해당 경로들은 접근을 허용
    		.requestMatchers("/", "/login/loginForm", "/resources/**")
			.permitAll() // 해당 경로들은 접근을 허용
			.anyRequest() // 다른 모든 요청은
			.authenticated() // 인증된 유저만 접근을 허용
		)
    	.addFilterBefore(jsonUsernamePasswordLoginFilter(), UsernamePasswordAuthenticationFilter.class)
		.formLogin(login -> login
			.usernameParameter("email")
			.passwordParameter("password")
			.loginPage("/login/loginForm") // 해당 주소로 로그인 페이지를 호출한다.
			.loginProcessingUrl("/login") // 해당 URL로 요청이 오면 스프링 시큐리티가 가로채서 로그인처리를 한다. -> loadUserByName
			.successHandler(authSucessHandler) // 성공시 요청을 처리할 핸들러
			.failureHandler(authFailureHandler) // 실패시 요청을 처리할 핸들러
		) // 로그인 폼은
		.logout(logout -> logout
			.logoutRequestMatcher(new AntPathRequestMatcher("/login/logout")) // 로그아웃 URL
		    .logoutSuccessUrl("/login/loginForm") // 성공시 리턴 URL
		    .invalidateHttpSession(true) // 인증정보를 지우하고 세션을 무효화
		    .deleteCookies("JSESSIONID") // JSESSIONID 쿠키 삭제
			.permitAll()
		)
    	.sessionManagement(session -> {
			try {
				session
				    .maximumSessions(1) // 세션 최대 허용 수 1, -1인 경우 무제한 세션 허용
				    .maxSessionsPreventsLogin(false) // true면 중복 로그인을 막고, false면 이전 로그인의 세션을 해제
				    // 세션이 만료된 경우 이동 할 페이지를 지정
				    .expiredUrl("/login/loginForm?error=true&exception=" + URLEncoder.encode("세션이 만료되었습니다. 다시 로그인 해주세요", "UTF-8"));
			} catch (UnsupportedEncodingException e) {
				e.printStackTrace();
			}
		} 
		);
        return http.build();
	}
	
	// 인증 관리자 관련 설정
		@Bean
		public DaoAuthenticationProvider daoAuthenticationProvider() throws Exception {
			DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();

			daoAuthenticationProvider.setUserDetailsService(memberService);
			daoAuthenticationProvider.setPasswordEncoder(encryptPassword());

			return daoAuthenticationProvider;
		}

		@Bean
		public AuthenticationManager authenticationManager() throws Exception {//AuthenticationManager 등록
			DaoAuthenticationProvider provider = daoAuthenticationProvider();//DaoAuthenticationProvider 사용
			provider.setPasswordEncoder(encryptPassword());//
			return new ProviderManager(provider);
		}

		@Bean
		public JsonUsernamePasswordAuthenticationFilter jsonUsernamePasswordLoginFilter() throws Exception {
			JsonUsernamePasswordAuthenticationFilter jsonUsernamePasswordLoginFilter = new JsonUsernamePasswordAuthenticationFilter();
			jsonUsernamePasswordLoginFilter.setAuthenticationManager(authenticationManager());
			return jsonUsernamePasswordLoginFilter;
		}	

}
