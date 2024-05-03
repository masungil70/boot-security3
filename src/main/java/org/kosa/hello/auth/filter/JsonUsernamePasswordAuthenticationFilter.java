package org.kosa.hello.auth.filter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.StreamUtils;

import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class JsonUsernamePasswordAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
	
	private static final String DEFAULT_LOGIN_REQUEST_URL = "/login";  // /login/oauth2/ + ????? 로 오는 요청을 처리할 것이다
	private static final String HTTP_METHOD = "POST";    //HTTP 메서드의 방식은 POST 이다.
	private static final String CONTENT_TYPE = "application/json";//json 타입의 데이터로만 로그인을 진행한다.
	private static final String USERNAME_KEY = "email";
	private static final String PASSWORD_KEY = "password";
	private static final AntPathRequestMatcher DEFAULT_LOGIN_PATH_REQUEST_MATCHER =
			new AntPathRequestMatcher(DEFAULT_LOGIN_REQUEST_URL, HTTP_METHOD); //=>   /login 의 요청에, POST로 온 요청에 매칭
	private ObjectMapper objectMapper = new ObjectMapper();
	
	public JsonUsernamePasswordAuthenticationFilter() {
		super(DEFAULT_LOGIN_PATH_REQUEST_MATCHER);
		
		//성공시 처리 핸들러 (json 으로 리턴) 
		setAuthenticationSuccessHandler((request, response, authentication) -> {
			response.setContentType(CONTENT_TYPE + "; charset=UTF-8");
			Map<String, Object> result = new HashMap<>();
			result.put("status", 0);
			result.put("statusMessage", "성공");
			response.getWriter().append(objectMapper.writeValueAsString(result));
		});
		
		//실패시 처리 핸들러 (json 으로 리턴)
		setAuthenticationFailureHandler((request, response, exception) -> {
			log.info("exception = {}", exception);
			response.setContentType(CONTENT_TYPE + "; charset=UTF-8");
			Map<String, Object> result = new HashMap<>();
			result.put("status", 1);
			result.put("statusMessage", "실패 : " + exception.toString());
			response.getWriter().append(objectMapper.writeValueAsString(result));
		});
		
	}
	

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException, IOException, ServletException {

		//요청시 context type이 json 인지 확인 함  
		if(request.getContentType() == null || !request.getContentType().startsWith(CONTENT_TYPE)  ) {
			throw new AuthenticationServiceException("Authentication Content-Type not supported: " + request.getContentType());
		}

		//요청 정보를 문자열로 얻는다   
		String messageBody = StreamUtils.copyToString(request.getInputStream(), StandardCharsets.UTF_8);
		log.info("messageBody {}", messageBody);
		
		//json 문자열을 Map 객체로 변환한다  
		Map<String, String> map = objectMapper.readValue(messageBody, Map.class);

		String username = map.get(USERNAME_KEY);
		String password = map.get(PASSWORD_KEY);

		//UsernamePasswordAuthenticationToken클래스에 principal 과 credentials 전달 전달하여 
		//UserDetailsService.loadUserByUsername()을 호출할 수 있게 한다
		return this.getAuthenticationManager().authenticate(new UsernamePasswordAuthenticationToken(username, password));
	}
}
