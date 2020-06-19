package com.demo.config.auth.imagecode;

import java.io.IOException;
import java.util.Objects;

import javax.annotation.Resource;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.lang3.StringUtils;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.ServletRequestBindingException;
import org.springframework.web.bind.ServletRequestUtils;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.filter.OncePerRequestFilter;

import com.demo.config.auth.handler.MyAuthenticationFailureHandler;
import com.demo.config.constant.SecurityContants;

/**
 * 自定义验证码 过滤器
 * 在spring中，filter都默认继承OncePerRequestFilter，但为什么要这样呢？
    OncePerRequestFilter顾名思义，他能够确保在一次请求只通过一次filter，而不需要重复执行
                    在servlet-2.3中，Filter会过滤一切请求，包括服务器内部使用forward转发请求和<%@ include file="/index.jsp"%>的情况。
                    到了servlet-2.4中Filter默认下只拦截外部提交的请求，forward和include这些内部转发都不会被过滤，但是有时候我们需要 forward的时候也用到Filter。
         因此，为了兼容各种不同的运行环境和版本，默认filter继承OncePerRequestFilter是一个比较稳妥的选择。
 */
@Component
public class CaptchaCodeFilter extends OncePerRequestFilter { //放到用户名密码登录过滤器之前执行,所以登陆之后的访问是不是进入的

    @Resource
    MyAuthenticationFailureHandler myAuthenticationFailureHandler;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {
        // 只有在登录请求时才有验证码校验
        if(StringUtils.equals("/login",request.getRequestURI())
                && StringUtils.equalsIgnoreCase(request.getMethod(),"post")){
            try{
                //验证谜底与用户输入是否匹配
                this.validate(new ServletWebRequest(request));
            }catch(AuthenticationException e){ // validate 抛出的异常可自定义继承 AuthenticationException
                myAuthenticationFailureHandler.onAuthenticationFailure(
                        request,response,e
                );
                //catch异常后,之后的过滤器就不再执行了
                return;
            }

        }
        filterChain.doFilter(request,response);
    }

    /**
     * 验证码 校验
     * @param request
     * @throws ServletRequestBindingException
     */
    private void validate(ServletWebRequest request) throws ServletRequestBindingException {

        HttpSession session = request.getRequest().getSession();

        String codeInRequest = ServletRequestUtils.getStringParameter(
                request.getRequest(),"captchaCode");
        if(StringUtils.isEmpty(codeInRequest)){
            throw new SessionAuthenticationException("验证码不能为空");
        }

        // 3. 获取session池中的验证码谜底
        CaptchaImageVO codeInSession = (CaptchaImageVO)
                session.getAttribute(SecurityContants.CAPTCHA_SESSION_KEY);
        if(Objects.isNull(codeInSession)) {
            throw new SessionAuthenticationException("验证码不存在");
        }

        // 4. 校验服务器session池中的验证码是否过期
        if(codeInSession.isExpired()) {
            session.removeAttribute(SecurityContants.CAPTCHA_SESSION_KEY);
            throw new SessionAuthenticationException("验证码已经过期");
        }

        // 5. 请求验证码校验
        if(!StringUtils.equals(codeInSession.getCode(), codeInRequest)) {
            throw new SessionAuthenticationException("验证码不匹配");
        }

    }



}
