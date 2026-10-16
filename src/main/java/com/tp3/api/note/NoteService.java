package com.tp3.api.note;

import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;

@Service
public class NoteService {
    private final NoteRepository repo;

    public NoteService(NoteRepository repo) {
        this.repo = repo;
    }

    public List<Note> list(Authentication auth) {
        return repo.findAll().stream()
                .filter(n -> isAdmin(auth) || n.owner().equals(auth.getName()))
                .toList();
    }

    /** Controle anti-BOLA : l'objet doit appartenir a l'appelant (sauf ADMIN). */
    public Note getOwned(Long id, Authentication auth) {
        Note n = repo.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Note introuvable"));
        if (!isAdmin(auth) && !n.owner().equals(auth.getName())) {
            throw new AccessDeniedException("Acces refuse");
        }
        return n;
    }

    public Note create(NoteRequest req, Authentication auth) {
        // le proprietaire vient du jeton (sub), jamais du corps de la requete
        return repo.save(new Note(null, req.title(), req.content(), auth.getName()));
    }

    public Note update(Long id, NoteRequest req, Authentication auth) {
        Note existing = getOwned(id, auth);
        return repo.save(new Note(existing.id(), req.title(), req.content(), existing.owner()));
    }

    public void delete(Long id) {
        repo.findById(id).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Note introuvable"));
        repo.deleteById(id);
    }

    private boolean isAdmin(Authentication auth) {
        return auth.getAuthorities().stream().anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));
    }
}
