package com.jwtdemo.demoJwt.Controller;


import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/bieuquyet/admin")
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {
    @GetMapping
    @PreAuthorize("hasAuthority('admin:read')")
    public  ResponseEntity<String> get() {
        return ResponseEntity.ok("get successfull");
    }
    @PostMapping
    @PreAuthorize("hasAuthority('admin:create')")
    public ResponseEntity<String> post() {
        return ResponseEntity.ok("post successfull");
    }
    @PutMapping
    @PreAuthorize("hasAuthority('admin:update')")
    public ResponseEntity<String> put() {
        return ResponseEntity.ok("put successfull");
    }
    @DeleteMapping
    @PreAuthorize("hasAuthority('admin:delete')")
    public ResponseEntity<String> delete() {
        return ResponseEntity.ok("delete successfull");
    }
}
