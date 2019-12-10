package com.wotrd.ssoclient.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@Slf4j
@RestController
public class HiController {

    @Value("${server.port}")
    private String port;

    /**
     * 不需要任何权限，只要Header中的Token正确即可
     */
    @RequestMapping("hi")
    public String hi() {
        return "hi : " + ",i am from port: " + port;
    }

    /**
     * 需要ROLE_ADMIN权限
     */
//    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @RequestMapping("hello")
    public String hello() {
        return "hello you!";
    }

    /**
     * 获取当前认证用户的信息
     */
    @GetMapping("getPrincipal")
    public OAuth2Authentication getPrinciple(OAuth2Authentication oAuth2Authentication,
                                             Principal principal,
                                             Authentication authentication){
        log.info(oAuth2Authentication.getUserAuthentication().getAuthorities().toString());
        log.info(oAuth2Authentication.toString());
        log.info("principal.toString()" + principal.toString());
        log.info("principal.getName()" + principal.getName());
        log.info("authentication:" + authentication.getAuthorities().toString());

        return oAuth2Authentication;
    }
    @GetMapping("home")
    public String homePage(){
        return "HOME PAGE";
    }
}

