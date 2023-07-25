package com.example.auth.controllers;

import com.example.auth.domain.user.AuthenticationDTO;
import com.example.auth.domain.user.LoginResponseDTO;
import com.example.auth.domain.user.RegisterDTO;
import com.example.auth.domain.user.User;
import com.example.auth.infra.security.TokenService;
import com.example.auth.repositories.UserRepository;
import jakarta.validation.Valid;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("auth")
public class AuthenticationController {

    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private UserRepository repository;
    @Autowired
    private TokenService tokenService;

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody @Valid AuthenticationDTO data){
        var usernamePassword = new UsernamePasswordAuthenticationToken(data.login(), data.password());
        var auth = this.authenticationManager.authenticate(usernamePassword);

        String token = tokenService.generateToken((User) auth.getPrincipal());

        return ResponseEntity.status(HttpStatus.OK).body("Login finished! " + new LoginResponseDTO(token));
    }

    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody @Valid RegisterDTO data){
        if(this.repository.findByLogin(data.login()) != null) 
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Wrong login and/or password!");

        String encryptedPassword = new BCryptPasswordEncoder().encode(data.password());
        User newUser = new User(data.login(), encryptedPassword, data.role());

        this.repository.save(newUser);

        return ResponseEntity.status(HttpStatus.OK).body("Account created sucessfully");
    }

    @GetMapping("/users")
    public ResponseEntity<Object> users(){
        List<User> users = this.repository.findAll();
        if(!users.isEmpty()){
            return ResponseEntity.status(HttpStatus.FOUND).body(users);
        }
        //Isso nuna vai acontecer pq precisa estar autenticado kkk
        return ResponseEntity.status(HttpStatus.NO_CONTENT).body("There are not user on database!");
    }

    @PutMapping("/update/{id}")
    public ResponseEntity<Object> update(@PathVariable String id, @RequestBody @Valid RegisterDTO registerDTO){
        var user = this.repository.findById(id);
        
        if(!user.isEmpty()){
            User userFound = user.get();
            userFound.setLogin(registerDTO.login());
            userFound.setPassword(new BCryptPasswordEncoder().encode(registerDTO.password()));
            userFound.setRole(registerDTO.role());
            this.repository.save(userFound);
            return ResponseEntity.status(HttpStatus.OK).body(userFound);
        }
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body("User not found!");
    }

    @DeleteMapping("/delete/{id}")
    public ResponseEntity<Object> delete(@PathVariable String id){
        var users = this.repository.findById(id);
        if(!users.isEmpty()){
            var user = users.get();
            this.repository.delete(user);
            return ResponseEntity.status(HttpStatus.OK).body(user);
        }else{
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("User not found!");
        }
        
    }
}
