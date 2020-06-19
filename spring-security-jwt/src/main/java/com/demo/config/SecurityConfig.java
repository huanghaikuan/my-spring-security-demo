package com.demo.config;

import java.util.Arrays;

import javax.annotation.Resource;
import javax.sql.DataSource;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.demo.config.auth.handler.MyLogoutSuccessHandler;
import com.demo.config.auth.jwt.JwtAuthenticationTokenFilter;
import com.demo.service.MyUserDetailsService;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig  extends WebSecurityConfigurerAdapter {

    @Resource
    MyLogoutSuccessHandler myLogoutSuccessHandler;

    @Resource
    MyUserDetailsService myUserDetailsService;

    @Resource
    private DataSource datasource;

    @Resource
    private JwtAuthenticationTokenFilter jwtAuthenticationTokenFilter;


    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.csrf() //开启跨站csrf攻击防御（跨站请求伪造（英语：Cross-site request forgery））    只防 post delete 等修改请求（不防get,所以不要用get方法去修改数据）
            .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())//作用是本站所有的接口访问都要加上一个随机token(专门验证接口是本站的) withHttpOnlyFalse是前端脚本可获取
            .ignoringAntMatchers("/authentication") //要忽略掉 JwtAuthController 的登陆（拿令牌）接口
            .and()
                .cors() //开启跨域访问的配置（springboot的4种方式都可生效）    这里配置的是  bean:CorsConfigurationSource
            .and()
            .addFilterBefore(jwtAuthenticationTokenFilter,UsernamePasswordAuthenticationFilter.class)
                .logout()
                    .logoutUrl("/signout")
                    //.logoutSuccessUrl("/login.html")
                    .deleteCookies("JSESSIONID")
                    .logoutSuccessHandler(myLogoutSuccessHandler)
                .and()
                    .rememberMe()
                    .rememberMeParameter("remember-me-new")
                    .rememberMeCookieName("remember-me-cookie")
                    .tokenValiditySeconds(2 * 24 * 60 * 60)
                    .tokenRepository(persistentTokenRepository())
                 .and()
                    .authorizeRequests()
                    .antMatchers("/authentication","/refreshtoken").permitAll()
                    .antMatchers("/index").authenticated()
                    .anyRequest().access("@rabcService.hasPermission(request,authentication)")
                 .and()
                    .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS);

    }


    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(myUserDetailsService)
                .passwordEncoder(passwordEncoder());
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Override
    public void configure(WebSecurity web) {
        //将项目中静态资源路径开放出来
        web.ignoring()
                .antMatchers( "/css/**", "/fonts/**", "/img/**", "/js/**");
    }

    @Bean
    public PersistentTokenRepository persistentTokenRepository(){

        JdbcTokenRepositoryImpl tokenRepository = new JdbcTokenRepositoryImpl();
        tokenRepository.setDataSource(datasource);

        return tokenRepository;
    }

    @Bean(name = BeanIds.AUTHENTICATION_MANAGER)
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    
    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("http://localhost:8888"));
        configuration.setAllowedMethods(Arrays.asList("GET","POST"));
        configuration.applyPermitDefaultValues();

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
