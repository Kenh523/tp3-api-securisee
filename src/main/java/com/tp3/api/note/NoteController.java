package com.tp3.api.note;

import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/notes")
public class NoteController {
    private final NoteService service;

    public NoteController(NoteService service) {
        this.service = service;
    }

    @GetMapping
    @PreAuthorize("hasAnyRole('USER','ADMIN')")
    public List<NoteResponse> list(Authentication auth) {
        return service.list(auth).stream().map(NoteResponse::from).toList();
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAnyRole('USER','ADMIN')")
    public NoteResponse get(@PathVariable Long id, Authentication auth) {
        return NoteResponse.from(service.getOwned(id, auth));
    }

    @PostMapping
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<NoteResponse> create(@Valid @RequestBody NoteRequest req, Authentication auth) {
        return ResponseEntity.status(HttpStatus.CREATED).body(NoteResponse.from(service.create(req, auth)));
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasAnyRole('USER','ADMIN')")
    public NoteResponse update(@PathVariable Long id, @Valid @RequestBody NoteRequest req, Authentication auth) {
        return NoteResponse.from(service.update(id, req, auth));
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void delete(@PathVariable Long id) {
        service.delete(id);
    }
}
