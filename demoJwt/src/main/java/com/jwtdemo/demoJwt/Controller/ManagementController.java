package com.jwtdemo.demoJwt.Controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/bieuquyet/management")
public class ManagementController {


    @GetMapping
    public ResponseEntity<String> get() {
        System.out.println("successfull");
        return ResponseEntity.ok("manager get successfull");
    }
    @PostMapping
    public ResponseEntity<String> post() {
        return ResponseEntity.ok("manager post successfull");
    }
    @PutMapping
    public ResponseEntity<String> put() {
        return ResponseEntity.ok("manager put successfull");
    }
    @DeleteMapping
    public ResponseEntity<String> delete() {
        return ResponseEntity.ok("managerdelete successfull");
    }
}
