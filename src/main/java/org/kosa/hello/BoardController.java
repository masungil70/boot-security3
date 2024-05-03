package org.kosa.hello;

import java.security.Principal;

import org.kosa.hello.entity.MemberVO;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticatedPrincipal;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import lombok.extern.slf4j.Slf4j;

@Controller
@RequestMapping("/board")
@Slf4j
public class BoardController {
	
	@GetMapping("/list")
	public void list(Authentication authentication) {
		//spring security로 로그인 객체를 얻는다 
		//인증 후 로그인 객체를 가져오는 방법
		//2. Controller에서 Authentication 객체를 가져오는 방법
		MemberVO memberVO = (MemberVO) authentication.getPrincipal();
		log.info("board.list() 함수 호출 ");
		log.info("memberVO  = {}", memberVO);
		log.info("member_id = {}", authentication.getName());
		log.info("authorities = {}", memberVO.getAuthorities());
	}
	
	@GetMapping("/list2")
	public void list2(Principal principal) {
		//spring security로 로그인 객체를 얻는다 
		//인증 후 로그인 객체를 가져오는 방법
		//2. Controller에서 Principal 객체를 가져오는 방법
		MemberVO memberVO = (MemberVO)((UsernamePasswordAuthenticationToken) principal).getPrincipal();
		log.info("board.list2() 함수 호출 ");
		log.info("memberVO  = {}", principal);
	}
	
	@GetMapping("/list3")
	public void list3() {
		//spring security로 로그인 객체를 얻는다
		//인증 후 로그인 객체를 가져오는 방법
		//3. SecurityContextHolder에서 직접 가져오는 방법
		Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal(); 
		UserDetails userDetails = (UserDetails)principal; 
		String username = userDetails.getUsername(); 
		String password = userDetails.getPassword();
		
		log.info("list3 함수 호출 ");
		log.info("list3  username = {}", username);
		log.info("list3  password = {}", password);
	}
}
