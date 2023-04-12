package com.example.Authentication.Controller;

import com.example.Authentication.Entity.Product;
import com.example.Authentication.Entity.User;
import com.example.Authentication.Repository.ProductRepository;
import com.example.Authentication.Repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.annotation.security.RolesAllowed;
import java.util.List;

@RestController
@RequestMapping("/users")
public class UserController {
    @Autowired
    private UserRepository userRepository;

    @PostMapping
    @PreAuthorize("hasAuthority('ADMIN')")
    public ResponseEntity<User> addUser(@RequestBody User user){
        BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
        String password = bCryptPasswordEncoder.encode(user.getPassword());
        user.setPassword(password);
        User newUser = this.userRepository.save(user);
        return ResponseEntity.ok(newUser);
    }

    @GetMapping
    @PreAuthorize("hasAuthority('ADMIN')")
    public ResponseEntity<List<User>> getAllProducts(){
        List<User> allUsers = this.userRepository.findAll();
        return ResponseEntity.ok(allUsers);
    }
}
