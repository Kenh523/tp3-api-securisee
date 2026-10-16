package com.tp3.api.note;

import org.springframework.stereotype.Repository;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

@Repository
public class NoteRepository {
    private final Map<Long, Note> store = new ConcurrentHashMap<>();
    private final AtomicLong seq = new AtomicLong();

    public Note save(Note n) {
        Long id = n.id() != null ? n.id() : seq.incrementAndGet();
        Note saved = new Note(id, n.title(), n.content(), n.owner());
        store.put(id, saved);
        return saved;
    }

    public Optional<Note> findById(Long id) {
        return Optional.ofNullable(store.get(id));
    }

    public List<Note> findAll() {
        return new ArrayList<>(store.values());
    }

    public void deleteById(Long id) {
        store.remove(id);
    }
}
