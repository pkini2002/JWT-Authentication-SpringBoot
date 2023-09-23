package com.example.JWTAuthenticationSpringboot.services;

import com.example.JWTAuthenticationSpringboot.models.User;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Service
public class UserService {
    private List<User>store=new ArrayList<>();

    public UserService(){
        store.add(new User(UUID.randomUUID().toString(),"Prathiksha Kini",
                "gpkini2002@gmail.com"));
        store.add(new User(UUID.randomUUID().toString(),"Padmini Kini",
                "kinipadmini@gmail.com"));
        store.add(new User(UUID.randomUUID().toString(),"Mahalasa Kini",
                "kinimahalasa@gmail.com"));
        store.add(new User(UUID.randomUUID().toString(),"Gurudath Kini",
                "gurukini@gmail.com"));
    }

    public List<User>getUsers(){
        return this.store;
    }
}
