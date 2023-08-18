package com.coding404.jwt.user;

import org.apache.ibatis.annotations.Mapper;

import com.coding404.jwt.command.UserVO;

@Mapper
public interface UserMapper {

	//가입
	public void join(UserVO vo);

	public UserVO login(String username); //로그인
	
	
}
