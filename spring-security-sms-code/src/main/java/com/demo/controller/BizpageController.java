package com.demo.controller;

import javax.annotation.Resource;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

import com.demo.service.MethodELService;

@Controller
public class BizpageController {
    @Resource
    MethodELService methodELService;
    
//    // 登录
//    @PostMapping("/login")
//    public String index(String username,String password) {
//        return "index";
//    }

    // 登录成功之后的首页
    @GetMapping("/index")
    public String index() {
        return "index";
    }

    // 日志管理
    @GetMapping("/syslog")
    public String showOrder() {
        //methodELService.findAll();
        //methodELService.findOne();

        /*List<Integer> ids = new ArrayList<>();
        ids.add(1);
        ids.add(2);
        methodELService.delete(ids,null);*/

        //List<PersonDemo> pds = methodELService.findAllPD();
        
        return "syslog";
    }

    // 用户管理
    @GetMapping("/sysuser")
    public String addOrder() {
        return "sysuser";
    }

    // 具体业务一
    @GetMapping("/biz1")
    public String updateOrder() {
        return "biz1";
    }

    // 具体业务二
    @GetMapping("/biz2")
    public String deleteOrder() {
        return "biz2";
    }


}