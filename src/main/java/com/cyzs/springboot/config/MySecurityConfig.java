package com.cyzs.springboot.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

/**
 * @author xiaoH
 * @create 2019-05-10-13:35
 */
@EnableWebSecurity
public class MySecurityConfig extends WebSecurityConfigurerAdapter{

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //super.configure(http);
        http.authorizeRequests().antMatchers("/").permitAll()
                .antMatchers("/level1/**").hasRole("vip1")
                .antMatchers("/level2/**").hasRole("vip2")
                .antMatchers("/level3/**").hasRole("vip3");

        //开启自动配置的登录功能,没有登录没有权限就会来到登录页面
        // 1.  /login来登录页
        //2.重定向到/login?error表示登录失败,自定义登录页，发/userlogin请求
        //自定义登录页，get的请求来到登录页，post请求处理登录
        //
        http.formLogin().usernameParameter("user").passwordParameter("password").loginPage("/userlogin");

        //开启自动配置的注销功能
        //访问   /logout表示用户注销，清空session
        http.logout().logoutSuccessUrl("/");

        //开启记住我功能,"remember"自定义登录页记住我 name属性
        http.rememberMe().rememberMeParameter("remember");

    }

    //定义认证规则
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //super.configure(auth);
        auth.inMemoryAuthentication().withUser("wang").password("123456").roles("vip1","vip2").
                and().withUser("li").password("123456").roles("vip1","vip3");

    }
}
