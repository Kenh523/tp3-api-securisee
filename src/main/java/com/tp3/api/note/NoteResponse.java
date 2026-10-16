package com.tp3.api.note;

/** DTO de sortie : le proprietaire interne n'est pas divulgue. */
public record NoteResponse(Long id, String title, String content) {
    static NoteResponse from(Note n) {
        return new NoteResponse(n.id(), n.title(), n.content());
    }
}
