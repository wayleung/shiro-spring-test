package com.way.controller;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import com.way.vo.User;

@Controller

public class UserController {
	
	
	@RequestMapping(value="/subLogin",method=RequestMethod.POST,produces="application/json;charset=utf-8")
	@ResponseBody
	public String subLogin(User user) {
		Subject subject = SecurityUtils.getSubject();
		UsernamePasswordToken token = new UsernamePasswordToken(user.getUsername(), user.getPassword());
		
		try {
			subject.login(token);
		} catch (Exception e) {
			// TODO: handle exception
			return e.getMessage();
			//return "login fail";
		}
		return "login success";
	}
}
