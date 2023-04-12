package com.example.Authentication.Controller;

import com.example.Authentication.Entity.Product;
import com.example.Authentication.Repository.ProductRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import javax.annotation.security.RolesAllowed;
import javax.validation.Valid;
import java.util.List;

@RestController
@RequestMapping("/products")
public class ProductController {
    @Autowired
    private ProductRepository productRepository;

    @PostMapping
    @PreAuthorize("hasAuthority('USER')")
    public ResponseEntity<Product> addProduct(@RequestBody @Valid Product product){
        Product newProduct = this.productRepository.save(product);
        return ResponseEntity.ok(newProduct);
    }

    @GetMapping
    @PreAuthorize("hasAuthority('USER')")
    public ResponseEntity<List<Product>> getAllProducts(){
        List<Product> allProducts = this.productRepository.findAll();
        return ResponseEntity.ok(allProducts);
    }
}
