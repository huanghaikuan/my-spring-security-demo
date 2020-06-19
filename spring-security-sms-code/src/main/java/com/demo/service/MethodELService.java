package com.demo.service;

import static org.springframework.security.core.context.SecurityContextHolder.getContext;

import java.util.ArrayList;
import java.util.List;

import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.access.prepost.PreFilter;
import org.springframework.stereotype.Service;

import com.demo.entity.PersonDemo;

@Service
public class MethodELService {

    @PreAuthorize("hasRole('admin')")
    public List<PersonDemo> findAll(){
        return null;
    }


    @PostAuthorize("returnObject.name == authentication.name") // returnObject 表示返回的 Object(这里是 PersonDemo)
    public PersonDemo findOne(){
        String authName =
                getContext().getAuthentication().getName();
        System.out.println(authName);
        return new PersonDemo(authName);
    }

    @PreFilter(filterTarget="ids", value="filterObject%2==0") //传进来的ids如（1,2），1%2=0被过滤了，所以接收ids的值只有2
    public void delete(List<Integer> ids, List<String> usernames) {
        System.out.println();
    }

    //如登陆用户是：admin 返回的list只有admin(kobe被过滤掉了)
    @PostFilter("filterObject.name == authentication.name")
    public List<PersonDemo> findAllPD(){

        List<PersonDemo> list = new ArrayList<>();
        list.add(new PersonDemo("kobe"));
        list.add(new PersonDemo("admin"));

        return list;
    }

}
