package com.shivam.instagram.controller;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.GetMapping;
import com.shivam.instagram.service.CustomUserDetailService;
import com.shivam.instagram.service.UserService;
import com.shivam.instagram.dto.ResponseBody;
import com.shivam.instagram.entity.User;
import com.shivam.instagram.jwt.AccessTokenJwtUtil;
import com.shivam.instagram.repository.UserRepository;
import com.shivam.instagram.utils.CookieHandler;
import com.shivam.instagram.utils.Time;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.util.Optional;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.springframework.web.bind.annotation.RequestParam;






@RestController
public class UserController 
{


    @Autowired
    Time timeUtils = new Time();


    @Autowired 
    CustomUserDetailService userDetailService ;


    @Autowired
    UserService userService;


    @Autowired
    CookieHandler cookieHandler;


    @Autowired
    AuthenticationManager authenticationManager ;

    @Autowired
    UserRepository userRepository;

    @Autowired
    AccessTokenJwtUtil jwtUtil ;




  
    @PostMapping("/sign-in")
    public ResponseBody signUp(HttpServletResponse httpServletResponse ,@RequestBody Map<String,String> loginCredentials)
    {

        System.out.println("here");

        String userKey = loginCredentials.get("userKey");
        String password = loginCredentials.get("password");
        System.out.println(userKey+"---------"+password);

        ResponseBody responseBody = userService.authenticate(httpServletResponse,userKey, password);

        return responseBody;
    
    }


    @PostMapping("/sign-up")
    public ResponseBody signUp(@RequestBody UserWrapper userWrapper, HttpServletResponse httpServletResponse) 
    {
        
        User user = userService.saveUser(userWrapper,httpServletResponse);

        return new ResponseBody(true, 200, user, "User creation successful", "/sign-up");
    }
    


    @GetMapping("/cookie")
    public Cookie getCookie(HttpServletRequest httpServletRequest) {

        Cookie[] cookie = httpServletRequest.getCookies();

        Optional<Cookie> auth_token_cookie =  Arrays.stream(cookie).filter(each -> each.getName().equals("access_token")).findAny();

        return auth_token_cookie.get();
    }


    @GetMapping("/create-cookie")
    public String createCookie( HttpServletResponse httpServletResponse) {
        
        cookieHandler.setDesiredCookie(httpServletResponse, "refresh_token", "768726321678321873612783", 1000 * 60 * 60);
        return "Success";
    }
    
    
    
    @GetMapping("/getAllUser")
    public List<User> getAllUser() {

        System.out.println(userRepository.findAll());
        return userRepository.findAll();
    }
    
    
    
    
}
