package com.demo.config;

import javax.annotation.Resource;
import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

import com.demo.config.auth.MyAuthenticationFailureHandler;
import com.demo.config.auth.MyAuthenticationSuccessHandler;
import com.demo.config.auth.MyExpiredSessionStrategy;
import com.demo.config.auth.MyLogoutSuccessHandler;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Resource
    private MyAuthenticationSuccessHandler myAuthenticationSuccessHandler;

    @Resource
    private MyAuthenticationFailureHandler myAuthenticationFailureHandler;

    @Autowired
    private DataSource dataSource;
    
    @Autowired
    private MyLogoutSuccessHandler myLogoutSuccessHandler;
    /**
     * spring security 总体配置
     * @param http
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable() //禁用跨站csrf攻击防御，后面的章节会专门讲解
                    .rememberMe() //实现记住我自动登录配置，核心的代码只有这一行
                    .rememberMeParameter("remember-me") // 设置from表单“自动登录”勾选框的参数名称
                    .rememberMeCookieName("remember-me-cookie")  //保存在浏览器端的cookie的名称，如果不设置默认也是remember-me
                    .tokenValiditySeconds(2 * 24 * 60 * 60) //设置token的有效期，即多长时间内可以免除重复登录，单位是秒。
                    .tokenRepository(persistentTokenRepository()) //自定义 remember-me设置,从原来的从内存中获取token -> 从数据库中获取token信息
                .and()
                    .formLogin()
                    .loginPage("/login.html")//用户未登录时，访问任何资源都转跳到该路径，即登录页面
                    .loginProcessingUrl("/login")//登录表单form中action的地址，也就是处理认证请求的路径
                    .usernameParameter("uname") //登录表单的账号参数，不修改的话默认是username
                    .passwordParameter("pword") //登录表单中密码参数，不修改的话默认是password
                    .successHandler(myAuthenticationSuccessHandler)
                    .failureHandler(myAuthenticationFailureHandler)
                    /** 不要配置defaultSuccessUrl和failureUrl，否则自定义handler将失效。handler配置与URL配置只能二选一*/
                    //.defaultSuccessUrl("/index")//登录认证成功后默认转跳的路径
                    //.failureUrl("/login.html") //登录认证是被跳转页面
                .and()
                    .logout() //登出配置
                    .logoutUrl("/signout") //退出的接口
    //                .logoutSuccessUrl("/aftersignout.html") //退出成功后跳转的页面
                    .deleteCookies("JSESSIONID") //删除 cookie
                    .logoutSuccessHandler(myLogoutSuccessHandler) //自定义退出成功后的处理器(不能和logoutSuccessUrl一起使用)
                .and()
                    .authorizeRequests() //权限控制
                    .antMatchers("/login.html", "/login","aftersignout.html")
                        .permitAll()//不需要通过登录验证就可以被访问的资源路径
                    .antMatchers("/biz1", "/biz2") //需要对外暴露的资源路径
                        .hasAnyAuthority("ROLE_user", "ROLE_admin")  //user角色和admin角色都可以访问
                    .antMatchers("/syslog", "/sysuser")
                        .hasAnyRole("admin")  //admin角色可以访问
                    //.antMatchers("/syslog").hasAuthority("sys:log")
                    //.antMatchers("/sysuser").hasAuthority("sys:user")
                    .anyRequest().authenticated()
                .and()
                    .sessionManagement()//session管理
                    .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)  //默认开启session
                    .invalidSessionUrl("/login.html") //非法超时session跳转页面
                    .sessionFixation().migrateSession() //每次登录验证将创建一个新的session
                    .maximumSessions(1) //同一个用户最大的登录数量
                    .maxSessionsPreventsLogin(false) //true表示已经登录就不予许再次登录，false表示允许再次登录但是之前的登录会下线。
                    .expiredSessionStrategy(new MyExpiredSessionStrategy()); //session被下线(超时)之后的处理策略


    }

    /**
     * 用户配置
     * @param auth
     * @throws Exception
     */
    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("user")
                .password(passwordEncoder().encode("123456"))
                .roles("user")
                    .and()
                .withUser("admin")
                .password(passwordEncoder().encode("123456"))
                //.authorities("sys:log","sys:user")
                .roles("admin")
                    .and()
                .passwordEncoder(passwordEncoder());//配置BCrypt加密
    }

    /**
     * 密码编码器
     * @return
     */
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    /**
     * 静态资源访问
     * @param web
     */
    @Override
    public void configure(WebSecurity web) {
        //将项目中静态资源路径开放出来
        web.ignoring().antMatchers( "/css/**", "/fonts/**", "/img/**", "/js/**");
    }

    /**
     * 配置从数据库中获取token
     * @return
     */
    @Bean
    public PersistentTokenRepository persistentTokenRepository(){
        JdbcTokenRepositoryImpl tokenRepository = new JdbcTokenRepositoryImpl();
        tokenRepository.setDataSource(dataSource);
        return tokenRepository;
    }
}
