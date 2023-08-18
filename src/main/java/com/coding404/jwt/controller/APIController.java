package com.coding404.jwt.controller;

import java.net.http.HttpRequest;

import javax.servlet.http.HttpServletRequest;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.coding404.jwt.command.UserVO;
import com.coding404.jwt.security.config.JWTService;

@RestController //jwt는 서버를 넘나들기 때문에 restController를 사용
public class APIController {
	
	//로그인 기능으로 가정
	//부메랑 사이트에서 확인
	
//	{
//	    "username" : "aaa123",
//	    "password" : "xxx123123",
//	    "role" : "ROLE_USER"
//	}
	
	
	
//	@PostMapping("/login")
//	public ResponseEntity<String> login(@RequestBody UserVO vo) {
//		
//		//로그인 시도가 성공을 하면 토큰 생성
//		System.out.println(vo.toString());
//		
//		String token = JWTService.createToken(vo.getUsername());
//		
//		
//		
//		return new ResponseEntity<>(token, HttpStatus.OK);
//	}
//	
//	//사용자 정보 확인
//	//토큰을 헤더에 담아서 사용자 정보와 함께 요청
//	@PostMapping("/api/v1/getInfo")
//	public ResponseEntity<Object> getInfo(HttpServletRequest request) {
//		//헤더에 담긴 토큰
//		String token = request.getHeader("Authorization");
//		
//		//토큰의 무결성 검사
//		try {
//			
//			boolean result = JWTService.validateToken(token);
//			System.out.println("토큰무결성: "+result);
//			
//			//사용자 정보~~~~코드
//		} catch (Exception e) {
//			e.printStackTrace();
//			return new ResponseEntity<>("토큰위조", HttpStatus.UNAUTHORIZED);
//		}
//		
//		return new ResponseEntity<>("success getInfo", HttpStatus.OK);
//	}
	
	//시큐리티 요청 테스트
	@GetMapping("/api/v1/hello")
	public String hello() {
		return "<h3>hello</h3>";
	}
	
	//토큰 기반으로 한 사용자요청 정보 반환기능
	@PostMapping("/api/v1/getInfo")
	public ResponseEntity<Object> getInfo() {
		System.out.println("토큰이 있으면 호출됨(데이터베이스 연결처리)");
		return new ResponseEntity<>("데이터", HttpStatus.OK);
	}
	
	//회원가입 =>  토큰이 필요할까..?
	@PostMapping("/join")
	public ResponseEntity<Object> join() {
		return new ResponseEntity<>("가입성공", HttpStatus.OK);
	}

}
