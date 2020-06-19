package com.demo.service;

import java.util.List;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import com.demo.dao.MyRBACServiceMapper;

@Component("rabcService")
public class MyRBACService {

    private AntPathMatcher antPathMatcher = new AntPathMatcher();

    @Resource
    private MyRBACServiceMapper myRBACServiceMapper;

    /**
     * 判断某用户是否具有该request资源的访问权限
     */
    public boolean hasPermission(HttpServletRequest request,
                                 Authentication authentication){

        Object principal = authentication.getPrincipal();

        if(principal instanceof UserDetails){
            String username = ((UserDetails)principal).getUsername();

            List<String> urls = myRBACServiceMapper.findUrlsByUserName(username);
            System.out.println(urls+"---------------------"+request.getRequestURI()+"--"+antPathMatcher.match(urls.get(0),request.getRequestURI()));
            return urls.stream().anyMatch(
                    url -> antPathMatcher.match(url,request.getRequestURI())
            );

        }
        return false;
    }


}
